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
}
