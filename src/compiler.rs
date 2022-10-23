use crate::helpers::Helpers;
use crate::optimize;

use anyhow::{bail, Result};
use bpf_ins::{Instruction, MemoryOpLoadType, Register};
use btf::types::{QualifiedType, Type};
use btf::BtfTypes;
use peginator::PegParser;
use peginator_macro::peginate;

use std::collections::HashMap;
use std::str::FromStr;

peginate!(
    "
@export
ScriptDef = input:InputLine {NewLine exprs:Expression}$;

InputLine = 'fn' '(' [args:TypedArgument {',' args:TypedArgument}] ')';
TypedArgument = name:Ident ':' type_name:TypeDecl;
TypeDecl = [is_ref:ReferencePrefix] name:Ident;

Expression = @:Assignment | @:FunctionCall | @:Return;

Assignment = left:LValue [':' type_name:TypeDecl] '=' right:RValue;
FunctionCall = name:Ident '(' args:RValue {',' args:RValue} ')';
Return = 'return' [value:RValue];

Condition = left:LValue WhiteSpace op:Comparator WhiteSpace right:RValue;

RValue = @:Immediate | @:LValue;
LValue = [prefix:Prefix] name:Ident {derefs:DeReference};

DeReference = @:MemberAccess | @:ArrayIndex;

MemberAccess = '.' name:Ident;
ArrayIndex = '[' element:Immediate ']';

@string
Immediate = {'0'..'9'}+;

Comparator = @:Equals | @:NotEquals | @:LessThan | @:GreaterThan | @:LessOrEqual | @:GreaterOrEqual;
Equals = '==';
NotEquals = '!=';
LessThan = '<';
GreaterThan = '>';
LessOrEqual = '<=';
GreaterOrEqual = '>=';
ReferencePrefix = '&';
DeReferencePrefix = '*';

Prefix = @:ReferencePrefix | @:DeReferencePrefix;

@string
@no_skip_ws
Ident = {'a'..'z' | 'A'..'Z' | '_'} [{'a'..'z' | 'A'..'Z' | '_' | '0'..'9'}+];

@string
@no_skip_ws
WhiteSpace = {' ' | '\t'};

@string
@no_skip_ws
NewLine = {'\r' | '\n' | '\r\n'};
"
);

#[derive(Clone, Copy)]
enum VariableLocation {
    SpecialImmediate(u32),
    Stack(i16),
}

#[derive(Clone)]
struct VariableInfo {
    pub var_type: QualifiedType,
    pub location: VariableLocation,
}

pub struct Compiler<'a> {
    types: &'a BtfTypes,
    variables: HashMap<String, VariableInfo>,
    instructions: Vec<Instruction>,
    stack: u32,
    expr_num: u32,
}

impl<'a> Compiler<'a> {
    pub fn create(types: &'a BtfTypes) -> Self {
        Self {
            types,
            variables: HashMap::new(),
            instructions: vec![],
            stack: 0,
            expr_num: 1,
        }
    }

    pub fn capture(&mut self, name: &str, value: i64) {
        let info = VariableInfo {
            var_type: QualifiedType::int::<i64>(),
            location: VariableLocation::SpecialImmediate(value as u32),
        };
        self.variables.insert(name.to_string(), info);
    }

    fn resolve_type_by_id(&mut self, id: u32) -> Result<QualifiedType> {
        if let Some(t) = self.types.resolve_type_by_id(id) {
            return Ok(t);
        }

        bail!(
            "[Line {}] Bad BTF database: type id \"{}\" not found.",
            self.expr_num,
            id
        );
    }

    fn resolve_type_by_decl(&mut self, decl: &TypeDecl) -> Result<QualifiedType> {
        if let Some(mut t) = self.types.resolve_type_by_name(&decl.name) {
            if matches!(decl.is_ref, Some(ReferencePrefix)) {
                t.num_refs += 1;
            }
            return Ok(t);
        }

        bail!(
            "[Line {}] No type found with the name \"{}\".",
            self.expr_num,
            decl.name
        );
    }

    fn get_variable_by_name(&mut self, name: &str) -> Result<VariableInfo> {
        if let Some(info) = self.variables.get(name) {
            return Ok(info.clone());
        }

        bail!(
            "[Line {}] No variable with the name \"{}\".",
            self.expr_num,
            name
        );
    }

    fn parse_immediate<T: FromStr>(&mut self, s: &str) -> Result<T> {
        if let Ok(imm) = s.parse::<T>() {
            return Ok(imm);
        }

        bail!("[Line {}] Bad immediate value \"{}\".", self.expr_num, s);
    }

    fn get_stack(&self) -> i16 {
        -(self.stack as i16)
    }

    fn push_stack(&mut self, sz: u32) -> Result<i16> {
        if self.stack + sz > 512 {
            bail!(
                "[Line {}] Stack size exceeded 512 bytes with this assignment.",
                self.expr_num
            );
        }

        self.stack += sz;
        Ok(self.get_stack())
    }

    fn emit_push_immediate(
        &mut self,
        imm_str: &str,
        cast_type: &QualifiedType,
        use_offset: Option<i16>,
    ) -> Result<(i16, QualifiedType)> {
        let (sz, is_signed) = match &cast_type.base_type {
            Type::Integer(int) => (int.size, int.is_signed),
            Type::Void => (8, false),
            _ => {
                bail!(
                    "[Line {}] Can only assign immediates to integer/inferred types.",
                    self.expr_num
                );
            }
        };

        let offset = match use_offset {
            Some(off) => off,
            None => self.push_stack(sz)?,
        };

        let new_type = match (sz, is_signed) {
            (1, false) => {
                let imm = self.parse_immediate::<u8>(imm_str)?;
                self.instructions
                    .push(Instruction::store8(Register::R10, offset, imm as i8));
                QualifiedType::int::<u8>()
            }
            (1, true) => {
                let imm = self.parse_immediate::<i8>(imm_str)?;
                self.instructions
                    .push(Instruction::store8(Register::R10, offset, imm));
                QualifiedType::int::<i8>()
            }
            (2, false) => {
                let imm = self.parse_immediate::<u16>(imm_str)?;
                self.instructions
                    .push(Instruction::store16(Register::R10, offset, imm as i16));
                QualifiedType::int::<u16>()
            }
            (2, true) => {
                let imm = self.parse_immediate::<i16>(imm_str)?;
                self.instructions
                    .push(Instruction::store16(Register::R10, offset, imm));
                QualifiedType::int::<i16>()
            }
            (4, false) => {
                let imm = self.parse_immediate::<u32>(imm_str)?;
                self.instructions
                    .push(Instruction::store32(Register::R10, offset, imm as i32));
                QualifiedType::int::<u32>()
            }
            (4, true) => {
                let imm = self.parse_immediate::<i32>(imm_str)?;
                self.instructions
                    .push(Instruction::store32(Register::R10, offset, imm));
                QualifiedType::int::<i32>()
            }
            (8, false) => {
                let imm = self.parse_immediate::<u64>(imm_str)?;
                self.instructions
                    .push(Instruction::store64(Register::R10, offset, imm as i64));
                QualifiedType::int::<u64>()
            }
            (8, true) => {
                let imm = self.parse_immediate::<i64>(imm_str)?;
                self.instructions
                    .push(Instruction::store64(Register::R10, offset, imm));
                QualifiedType::int::<i64>()
            }
            _ => {
                bail!("[Line {}] Unsupported integer size.", self.expr_num);
            }
        };

        Ok((offset, new_type))
    }

    fn emit_push_register(&mut self, reg: Register) -> Result<i16> {
        let offset = self.push_stack(8)?;
        self.instructions
            .push(Instruction::storex64(Register::R10, offset, reg));
        Ok(offset)
    }

    fn emit_deref_register_to_stack(
        &mut self,
        reg: Register,
        cast_type: &QualifiedType,
        offset: i16,
    ) {
        if cast_type.get_size() == 8 {
            self.instructions.push(Instruction::loadx64(reg, reg, 0));
            self.instructions
                .push(Instruction::storex64(Register::R10, offset, reg));
            return;
        }

        /*
         * probe_read_kernel(stack + offset, cast_type.get_size(), reg)
         */
        self.instructions
            .push(Instruction::movx64(Register::R1, Register::R10));
        self.instructions
            .push(Instruction::add64(Register::R1, offset.into()));
        self.instructions.push(Instruction::mov64(
            Register::R2,
            cast_type.get_size() as i32,
        ));
        self.instructions
            .push(Instruction::movx64(Register::R3, reg));
        self.instructions
            .push(Instruction::call(Helpers::ProbeReadKernel as u32));
    }

    fn emit_push_lvalue(
        &mut self,
        lval: &LValue,
        cast_type: &QualifiedType,
        use_offset: Option<i16>,
    ) -> Result<(i16, QualifiedType)> {
        /*
         * This emits instructions to set R6 to a pointer to the lvalue, the type
         * of the lvalue is returned by the function into `var_type`.
         */
        let var_type = self.emit_set_register_to_lvalue_addr(Register::R6, lval)?;

        /*
         * If the cast type is `void` we "deduce" the type to be the type of the lvalue.
         */
        let mut real_type = if matches!(cast_type.base_type, Type::Void) {
            var_type.clone()
        } else {
            cast_type.clone()
        };

        /*
         * The effective type must match the type of the lvalue in size.
         */
        if real_type.get_size() != var_type.get_size() {
            bail!(
                "[Line {}] Cannot assign two types of different sizes.",
                self.expr_num
            );
        }

        /*
         * Makes enough space on the stack to hold the value.
         */
        let offset = match use_offset {
            Some(off) => off,
            None => self.push_stack(real_type.get_size())?,
        };

        /*
         * Lastly, handle the prefix, either reference (&), dereference (*), or nothing.
         */
        match lval.prefix {
            None => self.emit_deref_register_to_stack(Register::R6, &real_type, offset),
            Some(Prefix::DeReferencePrefix(_)) => {
                bail!(
                    "[Line {}] Dereferencing is no currently implemented.",
                    self.expr_num
                );
            }
            Some(Prefix::ReferencePrefix(_)) => {
                real_type.num_refs += 1;
                self.instructions
                    .push(Instruction::storex64(Register::R10, offset, Register::R6));
            }
        }

        Ok((offset, real_type.clone()))
    }

    fn emit_push_rvalue(
        &mut self,
        rval: &RValue,
        cast_type: &QualifiedType,
        use_offset: Option<i16>,
    ) -> Result<(i16, QualifiedType)> {
        match rval {
            RValue::Immediate(imm_str) => self.emit_push_immediate(imm_str, cast_type, use_offset),
            RValue::LValue(lval) => self.emit_push_lvalue(lval, cast_type, use_offset),
        }
    }

    fn emit_assign(&mut self, assign: &Assignment) -> Result<()> {
        let (cast_type, use_offset) =
            if let Ok(info) = &self.get_variable_by_name(&assign.left.name) {
                if assign.type_name.is_some() {
                    bail!(
                        "[Line {}] Can't re-type \"{}\" after first assignment.",
                        self.expr_num,
                        assign.left.name
                    );
                } else if let VariableLocation::Stack(off) = info.location {
                    (info.var_type.clone(), Some(off))
                } else {
                    bail!(
                        "[Line {}] Variable \"{}\" cannot be re-assigned.",
                        self.expr_num,
                        assign.left.name
                    );
                }
            } else if let Some(type_name) = &assign.type_name {
                let assign_type = self.resolve_type_by_decl(type_name)?;
                (assign_type, None)
            } else {
                (Default::default(), None)
            };

        let (offset, new_type) = self.emit_push_rvalue(&assign.right, &cast_type, use_offset)?;

        self.variables.insert(
            assign.left.name.clone(),
            VariableInfo {
                var_type: new_type,
                location: VariableLocation::Stack(offset),
            },
        );

        Ok(())
    }

    fn emit_deref_member_access(
        &mut self,
        reg: Register,
        qtype: &QualifiedType,
        member_access: &MemberAccess,
    ) -> Result<QualifiedType> {
        let st = match &qtype.base_type {
            Type::Struct(s) => s,
            _ => {
                bail!(
                    "[Line {}] Cannot member-dereference a variable that isn't a structure.",
                    self.expr_num,
                );
            }
        };

        let member = if let Some(m) = st.members.get(&member_access.name) {
            m
        } else {
            bail!(
                "[Line {}] Structure doesn't contain \"{}\" as a field.",
                self.expr_num,
                member_access.name,
            );
        };

        if member.offset % 8 != 0 {
            bail!(
                "[Line {}] Can't access bit-fields of a structure.",
                self.expr_num,
            );
        }

        let offset = (member.offset / 8) as i32;
        if offset > 0 {
            self.instructions.push(Instruction::add64(reg, offset));
        }

        self.resolve_type_by_id(member.type_id)
    }

    fn emit_deref_array_index(
        &mut self,
        reg: Register,
        qtype: &QualifiedType,
        array_index: &ArrayIndex,
    ) -> Result<QualifiedType> {
        let ar = match &qtype.base_type {
            Type::Array(a) => a,
            _ => {
                bail!(
                    "[Line {}] Cannot access an element of a type that isn't an array.",
                    self.expr_num
                );
            }
        };

        let element_type = self.resolve_type_by_id(ar.element_type)?;
        let element_index = self.parse_immediate::<i32>(&array_index.element)?;
        let offset = element_index * element_type.get_size() as i32;
        self.instructions.push(Instruction::add64(reg, offset));
        Ok(element_type)
    }

    fn emit_apply_derefs_to_reg(
        &mut self,
        reg: Register,
        var_type: &QualifiedType,
        derefs: &[DeReference],
    ) -> Result<QualifiedType> {
        if derefs.is_empty() {
            return Ok(var_type.clone());
        }

        if var_type.is_pointer() {
            self.instructions.push(Instruction::loadx64(reg, reg, 0));
        }

        let next_type = match &derefs[0] {
            DeReference::MemberAccess(ma) => self.emit_deref_member_access(reg, var_type, ma)?,
            DeReference::ArrayIndex(ai) => self.emit_deref_array_index(reg, var_type, ai)?,
        };

        self.emit_apply_derefs_to_reg(reg, &next_type, &derefs[1..])
    }

    fn emit_set_register_to_lvalue_addr(
        &mut self,
        reg: Register,
        lval: &LValue,
    ) -> Result<QualifiedType> {
        let info = self.get_variable_by_name(&lval.name)?;

        match info.location {
            VariableLocation::SpecialImmediate(_) => {
                bail!(
                    "[Line {}] Cannot assign a value to a special immediate variable.",
                    self.expr_num,
                );
            }
            VariableLocation::Stack(o) => {
                self.instructions
                    .push(Instruction::movx64(reg, Register::R10));
                self.instructions.push(Instruction::add64(reg, o.into()));
            }
        }

        self.emit_apply_derefs_to_reg(reg, &info.var_type, &lval.derefs)
    }

    fn emit_set_register_from_lvalue(
        &mut self,
        reg: Register,
        lval: &LValue,
        load_type: Option<MemoryOpLoadType>,
    ) -> Result<()> {
        let info = self.get_variable_by_name(&lval.name)?;
        if let VariableLocation::SpecialImmediate(v) = info.location {
            if !lval.derefs.is_empty() {
                bail!(
                    "[Line {}] Cannot dereference a special immediate variable.",
                    self.expr_num,
                );
            }

            let load_type = load_type.unwrap_or(MemoryOpLoadType::Void);
            self.instructions
                .push(Instruction::loadtype(reg, v.into(), load_type));
            return Ok(());
        }

        let var_type = self.emit_set_register_to_lvalue_addr(reg, lval)?;

        /*
         * the register is already holding a pointer to the lvalue so, if a reference
         * was specified, nothing else needs to be done.
         */
        if matches!(lval.prefix, Some(Prefix::ReferencePrefix(_))) {
            return Ok(());
        }

        /*
         * register is pointing to a value of type `var_type`, load it into the register,
         * if it fits.
         */
        match var_type.get_size() {
            1 => self.instructions.push(Instruction::loadx8(reg, reg, 0)),
            2 => self.instructions.push(Instruction::loadx16(reg, reg, 0)),
            4 => self.instructions.push(Instruction::loadx32(reg, reg, 0)),
            8 => self.instructions.push(Instruction::loadx64(reg, reg, 0)),
            _ => {
                bail!(
                    "[Line {}] Variable too large to be passed in a register.",
                    self.expr_num,
                );
            }
        }

        /*
         * the register is now holding `var_type`. if another dereference was requested
         * then make sure the type being held by the register is a pointer.
         */
        if matches!(lval.prefix, Some(Prefix::DeReferencePrefix(_))) {
            if !var_type.is_pointer() {
                bail!(
                    "[Line {}] Cannot reference a non-pointer type.",
                    self.expr_num,
                );
            }

            self.instructions.push(Instruction::loadx64(reg, reg, 0));
        }

        Ok(())
    }

    fn emit_set_register_from_rvalue(
        &mut self,
        reg: Register,
        rval: &RValue,
        load_type: Option<MemoryOpLoadType>,
    ) -> Result<()> {
        match rval {
            RValue::Immediate(imm_str) => {
                if let Some(load_type) = load_type {
                    let imm = self.parse_immediate(imm_str)?;
                    self.instructions
                        .push(Instruction::loadtype(reg, imm, load_type));
                } else {
                    let imm = self.parse_immediate(imm_str)?;
                    self.instructions.push(Instruction::mov64(reg, imm));
                }
            }
            RValue::LValue(lval) => {
                self.emit_set_register_from_lvalue(reg, lval, load_type)?;
            }
        }

        Ok(())
    }

    fn emit_call(&mut self, call: &FunctionCall) -> Result<()> {
        let helper = match Helpers::from_string(&call.name) {
            Some(helper) => helper,
            None => {
                bail!(
                    "[Line {}] Unknown helper function \"{}\".",
                    self.expr_num,
                    call.name,
                );
            }
        };

        let types = helper.get_arg_types();

        for (i, arg) in call.args.iter().enumerate() {
            match i {
                0 => self.emit_set_register_from_rvalue(Register::R1, arg, Some(types[i]))?,
                1 => self.emit_set_register_from_rvalue(Register::R2, arg, Some(types[i]))?,
                2 => self.emit_set_register_from_rvalue(Register::R3, arg, Some(types[i]))?,
                3 => self.emit_set_register_from_rvalue(Register::R4, arg, Some(types[i]))?,
                4 => self.emit_set_register_from_rvalue(Register::R5, arg, Some(types[i]))?,
                _ => {
                    bail!(
                        "[Line {}] Function calls can have a maximum of 5 arguments.",
                        self.expr_num,
                    );
                }
            };
        }
        self.instructions.push(Instruction::call(helper as u32));

        Ok(())
    }

    fn emit_return(&mut self, ret: &Return) -> Result<()> {
        match &ret.value {
            None => {
                self.instructions.push(Instruction::mov64(Register::R0, 0));
                self.instructions.push(Instruction::exit());
            }
            Some(value) => {
                self.emit_set_register_from_rvalue(Register::R0, value, None)?;
                self.instructions.push(Instruction::exit());
            }
        }

        Ok(())
    }

    fn emit_prologue(&mut self, ast: &ScriptDef) -> Result<()> {
        /*
         * BPF limits the number of function arguments to 5 (R1 to R5).
         */
        if ast.input.args.len() > 5 {
            bail!(
                "[Line {}] Function calls can have a maximum of 5 arguments.",
                self.expr_num,
            );
        }

        /*
         * Push all input arguments to the stack and create variables entries for them.
         */
        for (i, arg) in ast.input.args.iter().enumerate() {
            let register = Register::from_num((i + 1) as u8).expect("too many args");
            let arg_type = self.resolve_type_by_decl(&arg.type_name)?;
            let offset = self.emit_push_register(register)?;
            self.variables.insert(
                arg.name.clone(),
                VariableInfo {
                    var_type: arg_type,
                    location: VariableLocation::Stack(offset),
                },
            );
        }

        Ok(())
    }

    fn emit_body(&mut self, ast: &ScriptDef) -> Result<()> {
        for expr in &ast.exprs {
            self.expr_num += 1;

            match expr {
                Expression::Assignment(assign) => {
                    self.emit_assign(assign)?;
                }
                Expression::FunctionCall(call) => {
                    self.emit_call(call)?;
                }
                Expression::Return(ret) => {
                    self.emit_return(ret)?;
                }
            }
        }

        /*
         * Programs implicitly return 0 when no return statement is specified.
         */
        let last = ast.exprs.last();
        if matches!(last, None) || !matches!(last, Some(Expression::Return(_))) {
            self.emit_return(&Return { value: None })?;
        }

        Ok(())
    }

    pub fn compile(&mut self, script_text: &str) -> Result<()> {
        let ast = ScriptDef::parse(script_text)?;
        self.emit_prologue(&ast)?;
        self.emit_body(&ast)?;

        self.instructions = optimize(&self.instructions);

        Ok(())
    }

    pub fn get_instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    pub fn get_bytecode(&self) -> Vec<u64> {
        let mut bytecode = vec![];
        for instruction in &self.instructions {
            let (n, x) = instruction.encode();
            bytecode.push(n);
            if let Some(x) = x {
                bytecode.push(x);
            }
        }

        bytecode
    }
}
