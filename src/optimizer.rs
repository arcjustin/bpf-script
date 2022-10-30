use bpf_ins::{Instruction, Opcode};

/// An [`Optimizer`] takes a set of input instructions and pushes optimized
/// instructions to the output (the second argument) if it succeeeds. On success
/// it should return `true`.
type Optimizer = fn(&mut &[Instruction], &mut Vec<Instruction>) -> bool;

/// Makes the following optimization:
///
///   r2 = r1   | r2 = *(r1 + N)
///   r2 += N   |
///   r2 = *r2  |
///
fn optimize_mov_add_load(inp: &mut &[Instruction], out: &mut Vec<Instruction>) -> bool {
    const NEEDED: usize = 3;
    if inp.len() < NEEDED {
        return false;
    }
    let (ins, rem) = inp.split_at(NEEDED);
    let load_size = if let Opcode::Memory(memory) = ins[2].get_opcode() {
        *memory.get_size()
    } else {
        return false;
    };

    let offset1: i16 = match ins[1].get_imm().try_into() {
        Ok(offset) => offset,
        Err(_) => return false,
    };

    let check0 = Instruction::movx64(ins[0].get_dst_reg(), ins[0].get_src_reg());
    let check1 = Instruction::add64(ins[1].get_dst_reg(), offset1.into());
    let check2 = Instruction::loadx(ins[2].get_dst_reg(), ins[2].get_src_reg(), 0, load_size);

    if check0 != ins[0] || check1 != ins[1] || check2 != ins[2] {
        return false;
    }

    *inp = rem;
    out.push(Instruction::loadx(
        ins[0].get_dst_reg(),
        ins[0].get_src_reg(),
        offset1,
        load_size,
    ));
    true
}

///
/// Makes the following optimization:
///
///   r2 += N   | r2 = *(r2 + N)
///   r2 = *r2  |
///
// I would think these could return Option<&'static [Instruction]>
fn optimize_add_load(inp: &mut &[Instruction], out: &mut Vec<Instruction>) -> bool {
    const NEEDED: usize = 2;
    if inp.len() < NEEDED {
        return false;
    }
    let (ins, rem) = inp.split_at(NEEDED);
    let load_size = if let Opcode::Memory(memory) = ins[1].get_opcode() {
        *memory.get_size()
    } else {
        return false;
    };

    let offset0: i16 = match ins[0].get_imm().try_into() {
        Ok(offset) => offset,
        Err(_) => return false,
    };

    let check0 = Instruction::add64(ins[0].get_dst_reg(), offset0.into());
    let check1 = Instruction::loadx(ins[1].get_dst_reg(), ins[1].get_src_reg(), 0, load_size);

    if check0 != ins[0] || check1 != ins[1] {
        return false;
    }

    *inp = rem;
    out.push(Instruction::loadx(
        ins[0].get_dst_reg(),
        ins[0].get_dst_reg(),
        offset0,
        load_size,
    ));
    true
}

fn no_optimization(inp: &mut &[Instruction], out: &mut Vec<Instruction>) -> bool {
    let (ins, rem) = match inp.split_first() {
        Some((ins, rem)) => (ins, rem),
        None => return false,
    };
    out.push(*ins);
    *inp = rem;
    true
}

/// List of optimizers used by the `optimize` function.
static OPTIMIZERS: [Optimizer; 3] = [optimize_mov_add_load, optimize_add_load, no_optimization];

/// Applies various optimizations to the given list of instructions.
///
/// # Arguments
///
/// * `instructions` - The program, as a list of instructions, to optimize.
pub fn optimize(mut instructions: &[Instruction]) -> Vec<Instruction> {
    let mut optimized = vec![];
    let instructions = &mut instructions;
    while !instructions.is_empty() {
        for optimizer in OPTIMIZERS {
            optimizer(instructions, &mut optimized);
        }
    }

    optimized
}
