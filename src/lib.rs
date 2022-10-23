pub mod compiler;
pub mod helpers;
mod optimizer;

pub use compiler::*;
pub use helpers::*;
use optimizer::*;

#[cfg(test)]
mod tests {
    use crate::Compiler;
    use bpf_ins::{Instruction, Register};
    use btf::BtfTypes;

    #[test]
    fn empty_program() {
        let prog = r#"
            fn()
        "#;

        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
        let mut compiler = Compiler::create(&btf);
        compiler.compile(prog).unwrap();

        let instructions = compiler.get_instructions();
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0], Instruction::mov64(Register::R0, 0));
        assert_eq!(instructions[1], Instruction::exit());
    }

    #[test]
    fn return_value() {
        let prog = r#"
            fn()
              return 300
        "#;

        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
        let mut compiler = Compiler::create(&btf);
        compiler.compile(prog).unwrap();

        let instructions = compiler.get_instructions();
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0], Instruction::mov64(Register::R0, 300));
        assert_eq!(instructions[1], Instruction::exit());
    }

    #[test]
    fn return_input_value() {
        let prog = r#"
            fn(a: int)
              return a
        "#;

        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
        let mut compiler = Compiler::create(&btf);
        compiler.compile(prog).unwrap();

        let instructions = compiler.get_instructions();
        assert_eq!(instructions.len(), 5);
        assert_eq!(
            instructions[0],
            Instruction::storex64(Register::R10, -8, Register::R1)
        );
        assert_eq!(
            instructions[1],
            Instruction::movx64(Register::R0, Register::R10)
        );
        assert_eq!(instructions[2], Instruction::add64(Register::R0, -8));
        assert_eq!(
            instructions[3],
            Instruction::loadx32(Register::R0, Register::R0, 0)
        );
        assert_eq!(instructions[4], Instruction::exit());
    }

    #[test]
    fn assign_fields() {
        let expected = [
            Instruction::store64(Register::R10, -16, 100), // *(r10 - 16) = 100
            Instruction::store64(Register::R10, -8, 200),  // *(r10 - 8) = 200
            Instruction::mov64(Register::R0, 0),           // r0 = 0
            Instruction::exit(),                           // exit
        ];

        let prog = r#"
            fn()
              vec: iovec = 0
              vec.iov_base = 100
              vec.iov_len = 200
        "#;

        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
        let mut compiler = Compiler::create(&btf);
        compiler.compile(prog).unwrap();
        for (i, ins) in compiler.get_instructions().iter().enumerate() {
            assert_eq!(ins, &expected[i]);
        }
    }

    #[test]
    fn assign_fields_from_fields() {
        let expected = [
            Instruction::storex64(Register::R10, -8, Register::R1), // *(r10 - 8) = r1
            Instruction::loadx64(Register::R6, Register::R10, -8),  // r6 = *(r10 - 8)
            Instruction::loadx64(Register::R6, Register::R6, 0),    // r6 = *r6
            Instruction::storex64(Register::R10, -24, Register::R6), // *(r10 - 24) = r6
            Instruction::loadx64(Register::R6, Register::R10, -8),  // r6 = *(r10 - 8)
            Instruction::loadx64(Register::R6, Register::R6, 8),    // r6 = *(r6 + 8)
            Instruction::storex64(Register::R10, -16, Register::R6), // *(r10 - 16) = r6
            Instruction::mov64(Register::R0, 50),                   // r0 = 50
            Instruction::exit(),                                    // exit
        ];

        let prog = r#"
            fn(vec: &iovec)
              vec_copy: iovec = 0
              vec_copy.iov_base = vec.iov_base
              vec_copy.iov_len = vec.iov_len
              return 50
        "#;

        let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
        let mut compiler = Compiler::create(&btf);
        compiler.compile(prog).unwrap();
        for (i, ins) in compiler.get_instructions().iter().enumerate() {
            assert_eq!(ins, &expected[i]);
        }
    }
}
