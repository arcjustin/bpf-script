# BPF Script

## Description
A small scripting language and compiler for creating eBPF programs at runtime.

## Example Usage
```rust
let prog = r#"
    fn(ctx: &bpf_raw_tracepoint_args)
        key = 300
        task: &task_struct = ctx.args[0]
        comm = task.comm
        map_update_elem(map, &key, &comm, 0)
"#;

let map = BpfHashMap::<u32, [u8; 16]>::create(10).unwrap();
let btf = BtfTypes::from_file("/sys/kernel/btf/vmlinux").unwrap();
let mut compiler = Compiler::create(&btf);
compiler.capture("map", map.get_identifier().into());
compiler.compile(prog).expect("compilation failed");
let instructions = compiler.get_instructions();
```

## TODO
- Add control flow.
