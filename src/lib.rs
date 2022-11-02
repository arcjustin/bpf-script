//! [![Build Status](https://github.com/arcjustin/bpf-script/workflows/build/badge.svg)](https://github.com/arcjustin/bpf-script/actions?query=workflow%3Abuild)
//! [![crates.io](https://img.shields.io/crates/v/bpf-script.svg)](https://crates.io/crates/bpf-script)
//! [![mio](https://docs.rs/bpf-script/badge.svg)](https://docs.rs/bpf-script/)
//! [![Lines of Code](https://tokei.rs/b1/github/arcjustin/bpf-script?category=code)](https://tokei.rs/b1/github/arcjustin/bpf-script?category=code)
//!
//! A small scripting language and compiler for creating eBPF programs at runtime without bcc or llvm.
//!
//! The intent behind building this crate was to primarily learn more about BPF internals and, secondly, to provide a dependency-free way of writing BPF programs, using a higher-level language, that could be compiled at run-time without the need to shell out to a compiler and load/patch BPF from an ELF file.
//!
//! The syntax for the language resembles Rust with a lot of features stripped out. For example, a simple u/k probe program that calls a helper and returns the value looks like so:
//! ```rust
//! fn(regs: &bpf_user_pt_regs_t)
//!     a = get_current_uid_gid()
//!     map_push_elem(queue, &a, 0)
//!     return a
//! ```
//!
//! This crate is made to work together with the following crates but they are not required:
//! - `btf` A BTF parsing library.
//! - `bpf-script-derive` Allows you to seamlessly share types between Rust and this compiler.
//! - `bpf-api` Creating programs, probes, maps, etc.
//!
//! ## Usage
//!
//! For usage examples, see code located in [examples/](examples/) :
//!
//!   | Examples | Description |
//!   |----------|-------------|
//!   |[print-instructions](examples/print-instructions.rs)| Compiles a short program and prints the generated instructions|
//!
//! ## TODO
//!
//! * Add control flow.
//! * Write more thorough tests.
//!
//! ## License
//!
//! * [MIT license](http://opensource.org/licenses/MIT)
mod formats;
mod optimizer;

pub mod compiler;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::compiler::Compiler;
    use crate::types::{Field, TypeDatabase};
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
            Instruction::call(4),                                   // call #4 (probe_read)
            Instruction::loadx64(Register::R6, Register::R10, -8),  // r6 = *(r10 - 8)
            Instruction::add64(Register::R6, 8),                    // r6 += 8
            Instruction::movx64(Register::R1, Register::R10),       // r3 = r6
            Instruction::add64(Register::R1, -16),                  // r1 -= 16
            Instruction::mov64(Register::R2, 8),                    // r2 = 8
            Instruction::movx64(Register::R3, Register::R6),        // r3 = r6
            Instruction::call(4),                                   // call #4 (probe_read)
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
            Instruction::call(15), // call #15 (get_current_uid_gid)
            Instruction::storex64(Register::R10, -8, Register::R0), // *(r10 - 8) = r0
            Instruction::mov64(Register::R0, 0), // r0 = 0
            Instruction::exit(),   // exit
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
            Instruction::call(15),                        // call #15 (get_current_uid_gid)
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
            Instruction::call(15), // call #15 (get_current_uid_gid)
            Instruction::movx64(Register::R1, Register::R0), // r1 = r0
            Instruction::call(15), // call #15 (get_current_uid_gid)
            Instruction::exit(),   // exit
        ];

        compile_and_compare(prog, &expected);
    }
}
