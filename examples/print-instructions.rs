use bpf_script::Compiler;
use btf::BtfTypes;

fn main() {
    let prog = r#"
            fn(vec: &iovec)
              vec_copy: iovec = 0
              vec_copy.iov_base = vec.iov_base
              vec_copy.iov_len = vec.iov_len
              return 50
        "#;

    let btf =
        BtfTypes::from_file("/sys/kernel/btf/vmlinux").expect("Failed to parse sysfs BTF file.");
    let mut compiler = Compiler::create(&btf);
    compiler.compile(prog).unwrap();

    for ins in compiler.get_instructions() {
        println!("{}", ins);
    }
}
