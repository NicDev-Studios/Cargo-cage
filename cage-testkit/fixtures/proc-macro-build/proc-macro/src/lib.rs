use proc_macro::TokenStream;

#[proc_macro]
pub fn cage_identity(input: TokenStream) -> TokenStream {
    input
}
