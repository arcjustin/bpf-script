# bpf-script
[![Build Status](https://github.com/arcjustin/bpf-script/workflows/build/badge.svg)](https://github.com/arcjustin/bpf-script/actions?query=workflow%3Abuild)
[![crates.io](https://img.shields.io/crates/v/bpf-script.svg)](https://crates.io/crates/bpf-script)
[![mio](https://docs.rs/bpf-script/badge.svg)](https://docs.rs/bpf-script/)
[![Lines of Code](https://tokei.rs/b1/github/arcjustin/bpf-script?category=code)](https://tokei.rs/b1/github/arcjustin/bpf-script?category=code)

A small scripting language and compiler for creating eBPF programs at runtime without bcc or llvm.

The intent behind building this crate was to primarily learn more about BPF internals and, secondly, to provide a dependency-free way of writing BPF programs, using a higher-level language, that could be compiled at run-time without the need to shell out to a compiler and load/patch BPF from an ELF file.

The syntax for the language resembles Rust with a lot of features stripped out. For example, a simple u/k probe program that calls a helper and returns the value looks like so:
```rust 
fn(regs: &bpf_user_pt_regs_t)
    a = get_current_uid_gid()
    map_push_elem(queue, &a, 0)
    return a
```

This crate is made to work together with the following crates but they are not required:
* `btf` A BTF parsing library.
* `bpf-script-derive` Allows you to seamlessly share types between Rust and this compiler.
* `bpf-api` Creating programs, probes, maps, etc.

## Usage

For usage examples, see code located in [examples/](examples/) :

  | Examples | Description |
  |----------|-------------|
  |[print-instructions](examples/print-instructions.rs)| Compiles a short program and prints the generated instructions|

## TODO

* Add control flow.
* Write more thorough tests.

## License

* [MIT license](http://opensource.org/licenses/MIT)
