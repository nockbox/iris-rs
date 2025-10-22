use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Derive macro for implementing the Hashable trait.
///
/// This macro automatically implements Hashable for structs by creating
/// nested tuples of field references and calling .hash() on them.
///
/// # Example
///
/// ```ignore
/// #[derive(Hashable)]
/// struct MyStruct {
///     x: u64,
///     y: u64,
///     z: u64,
/// }
/// ```
///
/// Expands to:
///
/// ```ignore
/// impl Hashable for MyStruct {
///     fn hash(&self) -> Digest {
///         (&self.x, &(&self.y, &self.z)).hash()
///     }
/// }
/// ```
#[proc_macro_derive(Hashable)]
pub fn derive_hashable(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let hash_expr = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => {
                let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

                if field_names.is_empty() {
                    // Empty struct hashes as unit
                    quote! { ().hash() }
                } else if field_names.len() == 1 {
                    // Single field: just hash the field directly
                    let field = &field_names[0];
                    quote! { self.#field.hash() }
                } else {
                    // Multiple fields: create nested tuples
                    build_nested_tuple(&field_names)
                }
            }
            Fields::Unnamed(fields) => {
                let field_count = fields.unnamed.len();

                if field_count == 0 {
                    quote! { ().hash() }
                } else if field_count == 1 {
                    quote! { self.0.hash() }
                } else {
                    // Build nested tuples for tuple structs using indices
                    let indices: Vec<_> = (0..field_count)
                        .map(|i| syn::Index::from(i))
                        .collect();
                    build_nested_tuple_indexed(&indices)
                }
            }
            Fields::Unit => {
                quote! { ().hash() }
            }
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                &input,
                "Hashable derive macro does not support enums yet",
            )
            .to_compile_error()
            .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &input,
                "Hashable derive macro does not support unions",
            )
            .to_compile_error()
            .into();
        }
    };

    let expanded = quote! {
        impl nbx_ztd::Hashable for #name {
            fn hash(&self) -> nbx_ztd::Digest {
                #hash_expr
            }
        }
    };

    TokenStream::from(expanded)
}

/// Build nested tuple expression for named fields: (&self.x, &(&self.y, &self.z))
fn build_nested_tuple(field_names: &[&Option<syn::Ident>]) -> proc_macro2::TokenStream {
    let mut iter = field_names.iter().rev();
    let last = iter.next().unwrap();

    let mut result = quote! { &self.#last };

    for field in iter {
        result = quote! { (&self.#field, #result) };
    }

    quote! { #result.hash() }
}

/// Build nested tuple expression for tuple struct fields: (&self.0, &(&self.1, &self.2))
fn build_nested_tuple_indexed(indices: &[syn::Index]) -> proc_macro2::TokenStream {
    let mut iter = indices.iter().rev();
    let last = iter.next().unwrap();

    let mut result = quote! { &self.#last };

    for index in iter {
        result = quote! { (&self.#index, #result) };
    }

    quote! { #result.hash() }
}
