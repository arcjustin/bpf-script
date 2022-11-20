use crate::compiler::Helpers;
use crate::error::{Error, Result as InternalResult, SemanticsErrorContext};
use crate::optimizer::optimize;
use crate::types::*;

use bpf_ins::{Instruction, JumpOperation, MemoryOpLoadType, Register};
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

Expression = @:Assignment | @:FunctionCall | @:Return | @:IfStatement;

Assignment = left:LValue [':' type_name:TypeDecl] '=' right:RValue;
FunctionCall = name:Ident '(' [args:RValue {',' args:RValue}] ')';
Return = 'return' [value:RValue];

Condition = left:RValue WhiteSpace op:Comparator WhiteSpace right:RValue;
IfStatement = 'if' cond:Condition '{' {exprs:Expression} '}' ['else' '{' {else_exprs:Expression} '}'];

RValue = @:FunctionCall | @:Immediate | @:LValue;
LValue = [prefix:Prefix] name:Ident {derefs:DeReference};

DeReference = @:FieldAccess | @:ArrayIndex;

FieldAccess = '.' name:Ident;
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
Ident = {'a'..'z' | 'A'..'Z' | '_' | '0'..'9'}+;

@string
@no_skip_ws
WhiteSpace = {' ' | '\t'};

@string
@no_skip_ws
NewLine = {'\r' | '\n' | '\r\n'};
"
);

macro_rules! semantics_bail {
    ($line: expr, $($message:expr),+) => {
        return Err(Error::Semantics {
            line: $line,
            message: format!($($message),+)
        });
    };
}

#[derive(Clone, Copy, Debug)]
enum VariableLocation {
    SpecialImmediate(u32),
    Stack(i16),
}

#[derive(Clone, Debug)]
struct VariableInfo {
    var_type: Type,
    location: VariableLocation,
}

pub struct Compiler<'a> {
    types: &'a TypeDatabase,
    variables: HashMap<String, VariableInfo>,
    instructions: Vec<Instruction>,
    stack: u32,
    expr_num: u32,
}

impl<'a> Compiler<'a> {
    const MAX_STACK_SIZE: u32 = 4096;

    /// Create a new compiler instance.
    ///
    /// # Arguments
    ///
    /// * `types` - The BTF type library to use when resolving types.
    ///
    /// # Example
    /// ```
    /// use bpf_script::compiler::Compiler;
    /// use bpf_script::types::TypeDatabase;
    ///
    /// let mut database = TypeDatabase::default();
    /// let mut compiler = Compiler::create(&database);
    /// ```
    pub fn create(types: &'a TypeDatabase) -> Self {
        Self {
            types,
            variables: HashMap::new(),
            instructions: vec![],
            stack: 0,
            expr_num: 1,
        }
    }

    /// Used to capture variables from the outer scope into the BPF
    /// program being compiled. This is mostly used to capture map
    /// identifers to pass to BPF helpers and for other integer values
    /// that need to be captured. In the future, this will be extended
    /// to capture arbitrary types making sharing between Rust and BPF
    /// more seamless.
    ///
    /// # Arguments
    ///
    /// `name` - The name of the variable when referenced from the script.
    /// `value` - The value of the variable.
    ///
    /// # Example
    /// ```
    /// use bpf_script::compiler::Compiler;
    /// use bpf_script::types::TypeDatabase;
    ///
    /// let mut database = TypeDatabase::default();
    /// let mut compiler = Compiler::create(&database);
    /// compiler.capture("outer", 0xdeadbeef);
    /// compiler.compile(r#"
    ///     fn()
    ///         return outer
    /// "#).expect("Failed to compile.");
    /// ```
    pub fn capture(&mut self, name: &str, value: i64) {
        let info = VariableInfo {
            var_type: BaseType::Integer(Integer {
                used_bits: 64,
                bits: 64,
                is_signed: false,
            })
            .into(),
            location: VariableLocation::SpecialImmediate(value as u32),
        };
        self.variables.insert(name.to_string(), info);
    }

    /// Helper function for resolving a type by `TypeDecl` and printing an error
    /// with line information, if it's not found.
    ///
    /// # Arguments
    ///
    /// * `decl` - The type declaration from the parsed ast.
    fn type_from_decl(&mut self, decl: &TypeDecl) -> InternalResult<Type> {
        let mut ty = self
            .types
            .get_type_by_name(&decl.name)
            .context(
                self.expr_num,
                &format!("Type with name \"{}\" doesn't exist", decl.name),
            )?
            .clone();

        if matches!(decl.is_ref, Some(ReferencePrefix)) {
            ty.num_refs += 1;
        }
        Ok(ty)
    }

    /// Helper function for finding a scoped variable by name and printing an error
    /// with line information, if it's not found.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the variable to retrieve.
    fn get_variable_by_name(&mut self, name: &str) -> InternalResult<VariableInfo> {
        if let Some(info) = self.variables.get(name) {
            return Ok(info.clone());
        }

        semantics_bail!(self.expr_num, "No variable with name \"{}\"", name);
    }

    /// Helper function for parsing an immediate value and printin an error with line
    /// information, if it's not found.
    ///
    /// # Arguments
    ///
    /// * `s` - The string representation of the immediate value.
    fn parse_immediate<T: FromStr>(&mut self, s: &str) -> InternalResult<T> {
        if let Ok(imm) = s.parse::<T>() {
            return Ok(imm);
        }

        semantics_bail!(self.expr_num, "Failed to parse immediate value \"{}\"", s);
    }

    /// Get the current stack offset.
    fn get_stack(&self) -> i16 {
        -(self.stack as i16)
    }

    /// Push the stack value by a given size and return the new offset. Verifies the
    /// new location doesn't overflow the stack and returns and error with line information,
    /// if it does.
    ///
    /// # Arguments
    ///
    /// * `size` - The number of bytes to push the stack.
    fn push_stack(&mut self, size: u32) -> InternalResult<i16> {
        if self.stack + size > Self::MAX_STACK_SIZE {
            semantics_bail!(
                self.expr_num,
                "Stack size exceeded {} bytes with this assignment",
                Self::MAX_STACK_SIZE
            );
        }

        self.stack += size;
        Ok(self.get_stack())
    }

    /// Emits instructions to initialize a portion of the stack, works like an
    /// abstract memset.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset to begin initializing.
    /// * `value` - The value to initialize _each byte_.
    /// * `size` - The number of bytes to initialize.
    fn emit_init_stack_range(&mut self, mut offset: i16, value: i8, mut size: u32) {
        let value = value as i64;
        let v64 = value
            | value << 8
            | value << 16
            | value << 24
            | value << 32
            | value << 40
            | value << 48
            | value << 56;
        let mut remaining = size;
        for _ in 0..size / 8 {
            self.instructions
                .push(Instruction::store64(Register::R10, offset, v64));
            remaining -= 8;
            offset += 8;
        }
        size = remaining;

        for _ in 0..size / 4 {
            self.instructions
                .push(Instruction::store32(Register::R10, offset, v64 as i32));
            remaining -= 4;
            offset += 4;
        }
        size = remaining;

        for _ in 0..size / 2 {
            self.instructions
                .push(Instruction::store16(Register::R10, offset, v64 as i16));
            remaining -= 2;
            offset += 2;
        }
        size = remaining;

        for _ in 0..size {
            self.instructions
                .push(Instruction::store8(Register::R10, offset, v64 as i8));
            remaining -= 1;
            offset += 1;
        }
    }

    /// Emits instructions that push the immediate value to the stack as the given type.
    ///
    /// # Arguments
    ///
    /// * `imm_str` - The string representation of the immediate value.
    /// * `cast_type` - The destination type.
    /// * `use_offset` - An optional offset at which the value is placed.
    fn emit_push_immediate(
        &mut self,
        imm_str: &str,
        cast_type: &Type,
        use_offset: Option<i16>,
    ) -> InternalResult<(i16, Type)> {
        let size = cast_type.get_size();
        if size == 0 && !matches!(cast_type.base_type, BaseType::Void) {
            semantics_bail!(self.expr_num, "Can't assign to zero-sized type");
        }

        let offset = match use_offset {
            Some(off) => off,
            None => self.push_stack(size)?,
        };

        if cast_type.is_pointer() {
            let imm = self.parse_immediate::<u8>(imm_str)?;
            self.instructions
                .push(Instruction::store8(Register::R10, offset, imm as i8));
            return Ok((offset, cast_type.clone()));
        }

        // No type was given so a 64-bit unsigned integer is inferred
        if matches!(cast_type.base_type, BaseType::Void) {
            let imm = self.parse_immediate::<i64>(imm_str)?;
            self.instructions
                .push(Instruction::store64(Register::R10, offset, imm));
            let new_type = BaseType::Integer(Integer {
                used_bits: 64,
                bits: 64,
                is_signed: false,
            });
            return Ok((offset, new_type.into()));
        }

        if let BaseType::Integer(integer) = &cast_type.base_type {
            match (size, integer.is_signed) {
                (1, false) => {
                    let imm = self.parse_immediate::<u8>(imm_str)?;
                    self.instructions
                        .push(Instruction::store8(Register::R10, offset, imm as i8));
                }
                (1, true) => {
                    let imm = self.parse_immediate::<i8>(imm_str)?;
                    self.instructions
                        .push(Instruction::store8(Register::R10, offset, imm));
                }
                (2, false) => {
                    let imm = self.parse_immediate::<u16>(imm_str)?;
                    self.instructions
                        .push(Instruction::store16(Register::R10, offset, imm as i16));
                }
                (2, true) => {
                    let imm = self.parse_immediate::<i16>(imm_str)?;
                    self.instructions
                        .push(Instruction::store16(Register::R10, offset, imm));
                }
                (4, false) => {
                    let imm = self.parse_immediate::<u32>(imm_str)?;
                    self.instructions
                        .push(Instruction::store32(Register::R10, offset, imm as i32));
                }
                (4, true) => {
                    let imm = self.parse_immediate::<i32>(imm_str)?;
                    self.instructions
                        .push(Instruction::store32(Register::R10, offset, imm));
                }
                (8, false) => {
                    let imm = self.parse_immediate::<u64>(imm_str)?;
                    self.instructions
                        .push(Instruction::store64(Register::R10, offset, imm as i64));
                }
                (8, true) => {
                    let imm = self.parse_immediate::<i64>(imm_str)?;
                    self.instructions
                        .push(Instruction::store64(Register::R10, offset, imm));
                }
                (bits, _) => {
                    semantics_bail!(self.expr_num, "{}-bit integers not supported", bits);
                }
            };
        } else {
            let imm = self.parse_immediate::<i8>(imm_str)?;
            self.emit_init_stack_range(offset, imm, size);
        }

        Ok((offset, cast_type.clone()))
    }

    /// Emits instructions that push a register to the stack. If an offset is given,
    /// the register is pushed to that offset.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register to for which a push is emitted.
    /// * `offset` - The stack offset to which the register is pushed.
    fn emit_push_register(&mut self, reg: Register, offset: Option<i16>) -> InternalResult<i16> {
        let offset = if let Some(offset) = offset {
            offset
        } else {
            self.push_stack(8)?
        };

        self.instructions
            .push(Instruction::storex64(Register::R10, offset, reg));
        Ok(offset)
    }

    /// Emits instructions that dereference a register to the stack using its
    /// currently held type. This always emits a `bpf_probe_read` call because
    /// only certain memory can be directly dereferenced by BPF instructions but
    /// all memory can be read through the helper.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register holding the address to dereference.
    /// * `deref_type` - The type of dereference.
    /// * `offset` - The offset in the stack to which the value is copied.
    fn emit_deref_register_to_stack(&mut self, reg: Register, deref_type: &Type, offset: i16) {
        self.instructions
            .push(Instruction::movx64(Register::R1, Register::R10));
        self.instructions
            .push(Instruction::add64(Register::R1, offset.into()));
        self.instructions.push(Instruction::mov64(
            Register::R2,
            deref_type.get_size() as i32,
        ));
        self.instructions
            .push(Instruction::movx64(Register::R3, reg));
        self.instructions
            .push(Instruction::call(Helpers::ProbeRead as u32));
    }

    /// Emits instructions that push an lvalue to the stack. Lvalues in this
    /// language are anything that occurs on the left side of an assignment.
    /// Currently, this is just stored variables.
    ///
    /// # Arguments
    ///
    /// * `lval` - The lvalue description.
    /// * `cast_type` - The destination type, this can differ on re-assignments.
    /// * `use_offset` - The (optional) offset at which the value should be stored.
    fn emit_push_lvalue(
        &mut self,
        lval: &LValue,
        cast_type: &Type,
        use_offset: Option<i16>,
    ) -> InternalResult<(i16, Type)> {
        // This emits instructions to set R6 to a pointer to the lvalue, the type
        // of the lvalue is returned by the function into `var_type`.
        let var_type = self.emit_set_register_to_lvalue_addr(Register::R6, lval)?;

        // If the cast type is `void` we "deduce" the type to be the type of the lvalue.
        let mut real_type = if matches!(cast_type.base_type, BaseType::Void) {
            var_type.clone()
        } else {
            cast_type.clone()
        };

        // The effective type must match the type of the lvalue in size.
        if real_type.get_size() != var_type.get_size() {
            semantics_bail!(self.expr_num, "Cannot assign two types of different sizes");
        }

        // Makes enough space on the stack to hold the value.
        let offset = match use_offset {
            Some(off) => off,
            None => self.push_stack(real_type.get_size())?,
        };

        // Lastly, handle the prefix, either reference (&), dereference (*), or nothing.
        match lval.prefix {
            None => self.emit_deref_register_to_stack(Register::R6, &real_type, offset),
            Some(Prefix::DeReferencePrefix(_)) => {
                semantics_bail!(self.expr_num, "Dereferencing is not currently supported");
            }
            Some(Prefix::ReferencePrefix(_)) => {
                real_type.num_refs += 1;
                self.instructions
                    .push(Instruction::storex64(Register::R10, offset, Register::R6));
            }
        }

        Ok((offset, real_type.clone()))
    }

    /// Emits instructions that push an rvalue to the stack. RValues in this language
    /// are anything that occur on the right hand side of an assignment: immediates,
    /// lvalues, function calls, etc.
    ///
    /// # Arguments
    ///
    /// * `rval` - The rvalue to be pushed to the stack.
    /// * `cast_type` - The type of the value, this can be different when casting.
    /// * `use_offset` - An optional offset to which the value is pushed.
    fn emit_push_rvalue(
        &mut self,
        rval: &RValue,
        cast_type: &Type,
        use_offset: Option<i16>,
    ) -> InternalResult<(i16, Type)> {
        match rval {
            RValue::Immediate(imm_str) => self.emit_push_immediate(imm_str, cast_type, use_offset),
            RValue::LValue(lval) => self.emit_push_lvalue(lval, cast_type, use_offset),
            RValue::FunctionCall(call) => {
                if let BaseType::Integer(integer) = &cast_type.base_type {
                    if integer.get_size() != 8 {
                        semantics_bail!(
                            self.expr_num,
                            "Function return values can only be stored in 64-bit types"
                        );
                    }

                    self.emit_call(call)?;
                    let offset = self.emit_push_register(Register::R0, use_offset)?;
                    Ok((offset, cast_type.clone()))
                } else {
                    semantics_bail!(
                        self.expr_num,
                        "Function return values can only be stored in integer types"
                    );
                }
            }
        }
    }

    /// Returns the offset and type from a structure and field name.
    ///
    /// # Arguments
    ///
    /// * `structure` - The structure to access.
    /// * `field_name` - The field within the structure.
    fn get_field_access(
        &mut self,
        structure: &Type,
        field_name: &str,
    ) -> InternalResult<(u32, Type)> {
        let structure = if let BaseType::Struct(structure) = &structure.base_type {
            structure
        } else {
            semantics_bail!(self.expr_num, "Can't field-deref a non-structure type");
        };

        let field = structure.fields.get(field_name).context(
            self.expr_num,
            &format!("Field \"{}\" doesn't exist on type", field_name),
        )?;

        if field.offset % 8 != 0 {
            semantics_bail!(self.expr_num, "Bit-field accesses not supported");
        }

        let field_type = self
            .types
            .get_type_by_id(field.type_id)
            .context(self.expr_num, "Internal error; type id invalid")?;
        Ok((field.offset / 8, field_type.clone()))
    }

    /// Returns the offset and type given an array and index.
    ///
    /// # Arguments
    ///
    /// * `array` - The array to access.
    /// * `index` - The index into the array.
    fn get_array_index(&mut self, array: &Type, index: &str) -> InternalResult<(u32, Type)> {
        let array = if let BaseType::Array(array) = &array.base_type {
            array
        } else {
            semantics_bail!(self.expr_num, "Can't array-deref a non-array type");
        };

        let index = self.parse_immediate::<u32>(index)?;
        if index > array.num_elements {
            semantics_bail!(
                self.expr_num,
                "Out-of-bounds array access {}/{}",
                index,
                array.num_elements
            );
        }

        let element_type = self
            .types
            .get_type_by_id(array.element_type_id)
            .context(self.expr_num, "Internal error; type id invalid")?;

        let offset = element_type.get_size() * index;
        Ok((offset, element_type.clone()))
    }

    /// Given a type and deref slice, returns the offset of the deref and its type.
    ///
    /// # Arguments
    ///
    /// * `ty` - The type being dereferenced.
    /// * `derefs` - The list of derefs to apply to the type.
    fn get_deref_offset(
        &mut self,
        ty: &Type,
        derefs: &[DeReference],
    ) -> InternalResult<(i16, Type)> {
        let mut offset = 0;
        let mut cur_type = ty.clone();
        for deref in derefs.iter() {
            if cur_type.is_pointer() {
                semantics_bail!(
                    self.expr_num,
                    "Can't deref an offset through an indirection"
                );
            }

            let (off, ty) = match deref {
                DeReference::FieldAccess(ma) => self.get_field_access(&cur_type, &ma.name)?,
                DeReference::ArrayIndex(ai) => self.get_array_index(&cur_type, &ai.element)?,
            };

            offset += off;
            cur_type = ty;
        }

        let offset: i16 = offset
            .try_into()
            .context(self.expr_num, "Type is too large to deref")?;
        Ok((offset, cur_type))
    }

    /// Emit instructions for an assignment expression.
    ///
    /// # Arguments
    ///
    /// * `assign` - Information about the assignment.
    fn emit_assign(&mut self, assign: &Assignment) -> InternalResult<()> {
        let mut new_variable = true;
        let (cast_type, use_offset) =
            if let Ok(info) = &self.get_variable_by_name(&assign.left.name) {
                if assign.type_name.is_some() {
                    semantics_bail!(
                        self.expr_num,
                        "Can't re-type \"{}\" after first assignment",
                        assign.left.name
                    );
                } else if let VariableLocation::Stack(off) = info.location {
                    let (rel_off, offset_type) =
                        self.get_deref_offset(&info.var_type, &assign.left.derefs)?;
                    new_variable = false;
                    (offset_type, Some(off + rel_off))
                } else {
                    semantics_bail!(
                        self.expr_num,
                        "Variable \"{}\" cannot be re-assigned",
                        assign.left.name
                    );
                }
            } else if let Some(type_name) = &assign.type_name {
                let assign_type = self.type_from_decl(type_name)?;
                (assign_type, None)
            } else {
                (Default::default(), None)
            };

        let (offset, new_type) = self.emit_push_rvalue(&assign.right, &cast_type, use_offset)?;

        if new_variable {
            self.variables.insert(
                assign.left.name.clone(),
                VariableInfo {
                    var_type: new_type,
                    location: VariableLocation::Stack(offset),
                },
            );
        }

        Ok(())
    }

    /// From an address held in a register and a structure type, emits instructions that set
    /// the register value to the address of the field being accessed.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register holding the address of the structure.
    /// * `structure` - The structure's type.
    /// * `field_access` - Information about the field being accessed.
    fn emit_field_access(
        &mut self,
        reg: Register,
        structure: &Type,
        field_access: &FieldAccess,
    ) -> InternalResult<Type> {
        let (offset, field_type) = self.get_field_access(structure, &field_access.name)?;
        if offset > 0 {
            self.instructions
                .push(Instruction::add64(reg, offset as i32));
        }
        Ok(field_type)
    }

    /// From an address held in a register and an array type, emits instructions that set
    /// the register value to the address of the element being accessed.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register holding the address of the array.
    /// * `array` - The array's type.
    /// * `index` - Information about the index being accessed.
    fn emit_index_array(
        &mut self,
        reg: Register,
        array: &Type,
        index: &ArrayIndex,
    ) -> InternalResult<Type> {
        let (offset, element_type) = self.get_array_index(array, &index.element)?;
        if offset > 0 {
            self.instructions
                .push(Instruction::add64(reg, offset as i32));
        }
        Ok(element_type)
    }

    /// Given a register holding a `var_type` address, and a list of derefs, emits instructions
    /// that apply these derefs to the register. After the instructions are executed, `reg` will
    /// hold the address to the deref.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register holding the address to be dereferenced.
    /// * `var_type` - The type of variable being pointed to by `reg`.
    /// * `derefs` - A list of derefs to apply.
    fn emit_apply_derefs_to_reg(
        &mut self,
        reg: Register,
        var_type: &Type,
        derefs: &[DeReference],
    ) -> InternalResult<Type> {
        if derefs.is_empty() {
            return Ok(var_type.clone());
        }

        // If the current var_type is a pointer then this deref is through a pointer.
        // Before emiting instructions to access the structure or field, the address
        // needs to be loaded into the register.
        if var_type.is_pointer() {
            self.instructions.push(Instruction::loadx64(reg, reg, 0));
        }

        let next_type = match &derefs[0] {
            DeReference::FieldAccess(ma) => self.emit_field_access(reg, var_type, ma)?,
            DeReference::ArrayIndex(ai) => self.emit_index_array(reg, var_type, ai)?,
        };

        self.emit_apply_derefs_to_reg(reg, &next_type, &derefs[1..])
    }

    /// Given a register and lvalue information, emits instructions that set the
    /// register to the address of the lvalue being accessed. On success, the final
    /// type of the lval access is returned and `reg` will contain the address pointing
    /// to this type.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register to be set.
    /// * `lval` - The lvalue information.
    fn emit_set_register_to_lvalue_addr(
        &mut self,
        reg: Register,
        lval: &LValue,
    ) -> InternalResult<Type> {
        let info = self.get_variable_by_name(&lval.name)?;

        match info.location {
            VariableLocation::SpecialImmediate(_) => {
                semantics_bail!(
                    self.expr_num,
                    "Variable \"{}\" is a capture; captures can't be assigned to",
                    lval.name
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

    /// Given a register and lvalue information, emits instructions that set the
    /// register to the value of this lvalue access. This is different from
    /// `emit_set_register_to_lvalue_addr` in that the register receives the final
    /// dereferenced type, _not_ an address pointing to it.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register that receives the value.
    /// * `lval` - The lvalue information.
    /// * `load_type` - The BPF load type to use when setting the register value.
    fn emit_set_register_from_lvalue(
        &mut self,
        reg: Register,
        lval: &LValue,
        load_type: Option<MemoryOpLoadType>,
    ) -> InternalResult<()> {
        let info = self.get_variable_by_name(&lval.name)?;
        if let VariableLocation::SpecialImmediate(v) = info.location {
            if !lval.derefs.is_empty() {
                semantics_bail!(
                    self.expr_num,
                    "Can't dereference \"{}\"; it's a capture",
                    lval.name
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
            size => {
                semantics_bail!(
                    self.expr_num,
                    "The variable \"{}\" is {} bytes and is too large to be passed in a register",
                    lval.name,
                    size
                );
            }
        }

        /*
         * the register is now holding `var_type`. if another dereference was requested
         * then make sure the type being held by the register is a pointer.
         */
        if matches!(lval.prefix, Some(Prefix::DeReferencePrefix(_))) {
            if !var_type.is_pointer() {
                semantics_bail!(self.expr_num, "Cannot dereference a non-pointer type");
            }

            self.instructions.push(Instruction::loadx64(reg, reg, 0));
        }

        Ok(())
    }

    /// Given a register and rvalue information, emits instructions that set the
    /// register to the value of this lvalue access. This can either be an lvalue,
    /// in which case `emit_set_register_from_lvalue` is called, an immediate, or
    /// a function call.
    ///
    /// # Arguments
    ///
    /// * `reg` - The register that receives the value.
    /// * `lval` - The lvalue information.
    /// * `load_type` - The BPF load type to use when setting the register value.
    fn emit_set_register_from_rvalue(
        &mut self,
        reg: Register,
        rval: &RValue,
        load_type: Option<MemoryOpLoadType>,
    ) -> InternalResult<()> {
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
            RValue::FunctionCall(call) => {
                self.emit_call(call)?;
                if !matches!(reg, Register::R0) {
                    self.instructions
                        .push(Instruction::movx64(reg, Register::R0));
                }
            }
        }

        Ok(())
    }

    /// Emits instructions that perform a call.
    ///
    /// # Arguments
    ///
    /// * `call` - Information about the call.
    fn emit_call(&mut self, call: &FunctionCall) -> InternalResult<()> {
        let helper = match Helpers::from_string(&call.name) {
            Some(helper) => helper,
            None => {
                semantics_bail!(self.expr_num, "Unknown function \"{}\"", call.name);
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
                    semantics_bail!(self.expr_num, "Function call exceeds 5 arguments");
                }
            };
        }
        self.instructions.push(Instruction::call(helper as u32));

        Ok(())
    }

    /// Emits instructions that perform an if statement.
    ///
    /// # Arguments
    ///
    /// * `if_statement` - The if statement information.
    fn emit_if_statement(&mut self, if_statement: &IfStatement) -> InternalResult<()> {
        self.emit_set_register_from_rvalue(Register::R8, &if_statement.cond.left, None)?;
        self.emit_set_register_from_rvalue(Register::R9, &if_statement.cond.right, None)?;

        self.instructions = optimize(&self.instructions);

        let operation = match if_statement.cond.op {
            Comparator::Equals(_) => JumpOperation::IfEqual,
            Comparator::NotEquals(_) => JumpOperation::IfNotEqual,
            Comparator::GreaterThan(_) => JumpOperation::IfGreater,
            Comparator::GreaterOrEqual(_) => JumpOperation::IfGreaterOrEqual,
            Comparator::LessThan(_) => JumpOperation::IfLessThan,
            Comparator::LessOrEqual(_) => JumpOperation::IfLessThanOrEqual,
        };

        self.instructions.push(Instruction::jmp_ifx(
            Register::R8,
            operation,
            Register::R9,
            1,
        ));

        let else_index = self.instructions.len();
        self.instructions.push(Instruction::jmp_abs(0));

        self.emit_body(&if_statement.exprs)?;

        let end_index = self.instructions.len();
        if !if_statement.else_exprs.is_empty() {
            self.instructions.push(Instruction::jmp_abs(0));
        }

        let offset: i16 = (self.instructions.len() - else_index - 1).try_into()?;
        self.instructions[else_index] = Instruction::jmp_abs(offset);

        if !if_statement.else_exprs.is_empty() {
            self.emit_body(&if_statement.else_exprs)?;

            let offset: i16 = (self.instructions.len() - end_index - 1).try_into()?;
            self.instructions[end_index] = Instruction::jmp_abs(offset);
        }

        Ok(())
    }

    /// Emits instructions that perform a return.
    ///
    /// # Arguments
    ///
    /// * `ret` - Information about the return.
    fn emit_return(&mut self, ret: &Return) -> InternalResult<()> {
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

    /// Emits instructions that setup the function. Pushes arguments to the
    /// stack, sets their types, etc.
    ///
    /// # Arguments
    ///
    /// * `input` - Information about the function's input.
    fn emit_prologue(&mut self, input: &InputLine) -> InternalResult<()> {
        /*
         * BPF limits the number of function arguments to 5 (R1 to R5).
         */
        if input.args.len() > 5 {
            semantics_bail!(self.expr_num, "Function exceeds 5 arguments");
        }

        /*
         * Push all input arguments to the stack and create variables entries for them.
         */
        for (i, arg) in input.args.iter().enumerate() {
            let register = Register::from_num((i + 1) as u8).expect("too many args");
            let arg_type = self.type_from_decl(&arg.type_name)?;
            let offset = self.emit_push_register(register, None)?;
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

    /// Emits instructions for the list of expressions given.
    ///
    /// # Arguments
    ///
    /// * `exprs` - The expressions in the body.
    fn emit_body(&mut self, exprs: &[Expression]) -> InternalResult<()> {
        for expr in exprs {
            self.expr_num += 1;

            match expr {
                Expression::Assignment(assign) => {
                    self.emit_assign(assign)?;
                }
                Expression::FunctionCall(call) => {
                    self.emit_call(call)?;
                }
                Expression::IfStatement(if_statement) => {
                    self.emit_if_statement(if_statement)?;
                }
                Expression::Return(ret) => {
                    self.emit_return(ret)?;
                }
            }
        }

        self.instructions = optimize(&self.instructions);

        Ok(())
    }

    /// Compile a given script.
    ///
    /// # Arguments
    ///
    /// * `script_text` - The script to compile, as a string.
    ///
    /// # Example
    /// ```
    /// use bpf_script::compiler::Compiler;
    /// use bpf_script::types::TypeDatabase;
    ///
    /// let mut database = TypeDatabase::default();
    /// database.add_integer(Some("u32"), 4, false);
    /// let mut compiler = Compiler::create(&database);
    /// compiler.compile(r#"
    ///     fn(a: u32)
    ///         return a
    /// "#).expect("Failed to compile.");
    /// ```
    pub fn compile(&mut self, script_text: &str) -> InternalResult<()> {
        let ast = ScriptDef::parse(script_text)?;
        self.emit_prologue(&ast.input)?;
        self.emit_body(&ast.exprs)?;

        /*
         * Programs implicitly return 0 when no return statement is specified.
         */
        let last = ast.exprs.last();
        if matches!(last, None) || !matches!(last, Some(Expression::Return(_))) {
            self.emit_return(&Return { value: None })?;
        }

        Ok(())
    }

    /// Returns the internally held instructions after `compile` has been called.
    ///
    /// # Example
    /// ```
    /// use bpf_script::compiler::Compiler;
    /// use bpf_script::types::TypeDatabase;
    ///
    /// let mut database = TypeDatabase::default();
    /// database.add_integer(Some("u32"), 4, false);
    /// let mut compiler = Compiler::create(&database);
    /// compiler.compile(r#"
    ///     fn(a: u32)
    ///         return a
    /// "#).expect("Failed to compile.");
    /// for ins in compiler.get_instructions() {
    ///     println!("{}", ins);
    /// }
    /// ```
    pub fn get_instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    /// Returns the bytecode of a program after `compile` has been called. These
    /// are the raw instructions that make up a BPF program that can be passed
    /// directly to the kernel.
    ///
    /// # Example
    /// ```
    /// use bpf_script::compiler::Compiler;
    /// use bpf_script::types::TypeDatabase;
    ///
    /// let mut database = TypeDatabase::default();
    /// database.add_integer(Some("u32"), 4, false);
    /// let mut compiler = Compiler::create(&database);
    /// compiler.compile(r#"
    ///     fn(a: u32)
    ///         return a
    /// "#).expect("Failed to compile.");
    /// for ins in compiler.get_bytecode() {
    ///     println!("{}", ins);
    /// }
    /// ```
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
