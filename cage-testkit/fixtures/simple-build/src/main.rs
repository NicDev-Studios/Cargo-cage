fn main() {
    println!("cargo-cage fixture built");
}

#[test]
fn test_binary_runs_inside_the_sandbox() {
    assert_eq!(2 + 2, 4);
}
