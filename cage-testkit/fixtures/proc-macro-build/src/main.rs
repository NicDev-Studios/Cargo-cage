use cage_fixture_proc_macro::cage_identity;

fn main() {
    let value = cage_identity!("proc-macro ran inside cargo-cage");
    println!("{value}");
}
