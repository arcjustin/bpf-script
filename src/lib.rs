mod compiler;
mod error;
mod formats;
mod helpers;
mod optimizer;
mod types;

pub use compiler::Compiler;
pub use error::{Error, Result};
pub use helpers::Helpers;
pub use types::*;

#[cfg(test)]
mod tests {
    use crate::{Compiler, Field, Helpers, TypeDatabase};
    use bpf_ins::{Instruction, Register};

    fn compile_and_compare(prog: &str, expected: &[Instruction]) {
        let mut database = TypeDatabase::default();

        database
            .add_integer(Some("int"), 4, true)
            .expect("Failed to add type.");

        let u64id = database
            .add_integer(Some("__u64"), 8, false)
            .expect("Failed to add type.");

        let iov_base = Field {
            offset: 0,
            type_id: u64id,
        };

        let iov_len = Field {
            offset: 64,
            type_id: u64id,
        };

        database
            .add_struct(
                Some("iovec"),
                &[("iov_base", iov_base), ("iov_len", iov_len)],
            )
            .expect("Failed to add type.");

        let mut compiler = Compiler::create(&database);
        compiler.compile(prog).unwrap();

        let instructions = compiler.get_instructions();
        assert_eq!(instructions.len(), expected.len());
        for (i, ins) in instructions.iter().enumerate() {
            assert_eq!(ins, &expected[i]);
        }
    }

    #[test]
    fn empty_program() {
        let prog = r#"
            fn()
        "#;

        let expected = [
            Instruction::mov64(Register::R0, 0), // r0 = 0
            Instruction::exit(),                 // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn return_immediate() {
        let prog = r#"
            fn()
              return 300
        "#;

        let expected = [
            Instruction::mov64(Register::R0, 300), // r0 = 300
            Instruction::exit(),                   // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn return_input_value() {
        let prog = r#"
            fn(a: int)
              return a
        "#;

        let expected = [
            Instruction::storex64(Register::R10, -8, Register::R1), // *(r10 - 8) = r1
            Instruction::loadx32(Register::R0, Register::R10, -8),  // r0 = *(r10 - 8)
            Instruction::exit(),                                    // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn assign_fields() {
        let prog = r#"
            fn()
              vec: iovec = 0
              vec.iov_base = 100
              vec.iov_len = 200
        "#;

        let expected = [
            Instruction::store64(Register::R10, -16, 0), // *(r10 - 16) = 0
            Instruction::store64(Register::R10, -8, 0),  // *(r10 - 8) = 0
            Instruction::store64(Register::R10, -16, 100), // *(r10 - 16) = 100
            Instruction::store64(Register::R10, -8, 200), // *(r10 - 8) = 200
            Instruction::mov64(Register::R0, 0),         // r0 = 0
            Instruction::exit(),                         // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn assign_fields_from_fields() {
        let prog = r#"
            fn(vec: &iovec)
              vec_copy: iovec = 0
              vec_copy.iov_base = vec.iov_base
              vec_copy.iov_len = vec.iov_len
              return 50
        "#;

        let expected = [
            Instruction::storex64(Register::R10, -8, Register::R1), // *(r10 - 8) = r1
            Instruction::store64(Register::R10, -24, 0),            // *(r10 - 24) = 0
            Instruction::store64(Register::R10, -16, 0),            // *(r10 - 16) = 0
            Instruction::loadx64(Register::R6, Register::R10, -8),  // r6 = *(r10 - 8)
            Instruction::movx64(Register::R1, Register::R10),       // r1 = r10
            Instruction::add64(Register::R1, -24),                  // r1 -= 24
            Instruction::mov64(Register::R2, 8),                    // r2 = 8
            Instruction::movx64(Register::R3, Register::R6),        // r3 = r6
            Instruction::call(Helpers::ProbeRead as u32),           // call #3
            Instruction::loadx64(Register::R6, Register::R10, -8),  // r6 = *(r10 - 8)
            Instruction::add64(Register::R6, 8),                    // r6 += 8
            Instruction::movx64(Register::R1, Register::R10),       // r3 = r6
            Instruction::add64(Register::R1, -16),                  // r1 -= 16
            Instruction::mov64(Register::R2, 8),                    // r2 = 8
            Instruction::movx64(Register::R3, Register::R6),        // r3 = r6
            Instruction::call(Helpers::ProbeRead as u32),           // call #3
            Instruction::mov64(Register::R0, 50),                   // r0 = 50
            Instruction::exit(),                                    // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn assign_function_call() {
        let prog = r#"
            fn()
                a: __u64 = get_current_uid_gid()
        "#;

        let expected = [
            Instruction::call(Helpers::GetCurrentUidGid as u32), // call #15
            Instruction::storex64(Register::R10, -8, Register::R0), // *(r10 - 8) = r0
            Instruction::mov64(Register::R0, 0),                 // r0 = 0
            Instruction::exit(),                                 // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn return_function_call() {
        let prog = r#"
            fn()
                a: __u64 = 100
                return get_current_uid_gid()
        "#;

        let expected = [
            Instruction::store64(Register::R10, -8, 100), // *(r10 - 8) = 100
            Instruction::call(Helpers::GetCurrentUidGid as u32), // call #15
            Instruction::exit(),                          // exit
        ];

        compile_and_compare(prog, &expected);
    }

    #[test]
    fn return_nested_function_call() {
        let prog = r#"
            fn()
                return get_current_uid_gid(get_current_uid_gid())
        "#;

        let expected = [
            Instruction::call(Helpers::GetCurrentUidGid as u32), // call #15
            Instruction::movx64(Register::R1, Register::R0),     // r1 = r0
            Instruction::call(Helpers::GetCurrentUidGid as u32), // call #15
            Instruction::exit(),                                 // exit
        ];

        compile_and_compare(prog, &expected);
    }
}
