# bpf-script
[![Build Status](https://github.com/arcjustin/bpf-script/workflows/build/badge.svg)](https://github.com/arcjustin/bpf-script/actions?query=workflow%3Abuild)
[![crates.io](https://img.shields.io/crates/v/bpf-script.svg)](https://crates.io/crates/bpf-script)
[![mio](https://docs.rs/bpf-script/badge.svg)](https://docs.rs/bpf-script/)
[![Lines of Code](https://tokei.rs/b1/github/arcjustin/bpf-script?category=code)](https://tokei.rs/b1/github/arcjustin/bpf-script?category=code)

A small scripting language and compiler for creating eBPF programs at runtime.

The motive behind this crate and sister crates: `btf`, `btf-derive`, `bpf-ins`, and `bpf-api`, aside from learning more about eBPF, was to be able to have a fully Rust eBPF solution. That is, the ability to easily write, compile, and attach BPF programs and use maps without any dependencies on bcc, libbpf or any other non-Rust BPF dependencies.

## Usage

For usage examples, see code located in [examples/](examples/) :

  | Examples | Description |
  |----------|-------------|
  |[print-instructions](examples/print-instructions.rs)| Compiles a short program and prints the generated instructions|

## TODO
- Add control flow.
- Remove anyhow / add proper errors.
