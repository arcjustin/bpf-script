use bpf_script::{Compiler, Field, TypeDatabase};

fn main() {
    let prog = r#"
            fn(vec: &iovec)
              vec_copy: iovec = 0
              vec_copy.iov_base = vec.iov_base
              vec_copy.iov_len = vec.iov_len
              return 50
        "#;

    let mut database = TypeDatabase::default();

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

    for ins in compiler.get_instructions() {
        println!("{}", ins);
    }
}
