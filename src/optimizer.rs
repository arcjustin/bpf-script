use bpf_ins::{Instruction, Opcode};

struct Optimizer {
    pub num_instructions: usize,
    pub function: fn(&[Instruction]) -> Option<Vec<Instruction>>,
}

//
// Makes the following optimization:
//
//   r2 = r1   | r2 = *(r1 + N)
//   r2 += N   |
//   r2 = *r2  |
//
fn optimize_mov_add_load(ins: &[Instruction]) -> Option<Vec<Instruction>> {
    let load_size = if let Opcode::Memory(memory) = ins[2].get_opcode() {
        *memory.get_size()
    } else {
        return None;
    };

    let check0 = Instruction::movx64(ins[0].get_dst_reg(), ins[0].get_src_reg());
    let check1 = Instruction::add64(ins[1].get_dst_reg(), ins[1].get_imm().try_into().ok()?);
    let check2 = Instruction::loadx(ins[2].get_dst_reg(), ins[2].get_src_reg(), 0, load_size);

    if check0 != ins[0] || check1 != ins[1] || check2 != ins[2] {
        return None;
    }

    Some(vec![Instruction::loadx(
        ins[0].get_dst_reg(),
        ins[0].get_src_reg(),
        ins[1].get_imm().try_into().ok()?,
        load_size,
    )])
}

//
// Makes the following optimization:
//
//   r2 += N   | r2 = *(r2 + N)
//   r2 = *r2  |
//
fn optimize_add_load(ins: &[Instruction]) -> Option<Vec<Instruction>> {
    let check0 = Instruction::add64(ins[0].get_dst_reg(), ins[0].get_imm().try_into().ok()?);
    let check1 = Instruction::loadx64(ins[1].get_dst_reg(), ins[1].get_src_reg(), 0);

    if check0 != ins[0] || check1 != ins[1] {
        return None;
    }

    Some(vec![Instruction::loadx64(
        ins[0].get_dst_reg(),
        ins[0].get_dst_reg(),
        ins[0].get_imm().try_into().ok()?,
    )])
}

const OPTIMIZERS: [Optimizer; 2] = [
    Optimizer {
        num_instructions: 3,
        function: optimize_mov_add_load,
    },
    Optimizer {
        num_instructions: 2,
        function: optimize_add_load,
    },
];

pub fn optimize(instructions: &[Instruction]) -> Vec<Instruction> {
    let mut num_eliminated = 0;
    let mut optimized = vec![];
    'outer: for i in 0..instructions.len() {
        let start = usize::min(instructions.len(), i + num_eliminated);
        let remaining = &instructions[start..];
        if remaining.is_empty() {
            break;
        }

        for optimizer in OPTIMIZERS
            .iter()
            .filter(|o| o.num_instructions <= remaining.len())
        {
            if let Some(mut instructions) = (optimizer.function)(remaining) {
                optimized.append(&mut instructions);
                num_eliminated += optimizer.num_instructions - 1;
                continue 'outer;
            }
        }

        optimized.push(remaining[0]);
    }

    optimized
}
