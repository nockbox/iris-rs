use proc_macro::TokenStream;
use proc_macro2::Ident;
use proc_macro_crate::FoundCrate;
use quote::{format_ident, quote};
use syn::{parse_macro_input, token::PathSep, Data, DeriveInput, Fields};

fn get_crate_path() -> proc_macro2::TokenStream {
    let (col, ident) = crate_path_ident();
    quote!(#col #ident)
}

fn crate_path_ident() -> (Option<PathSep>, Ident) {
    match crate_path_fixed() {
        Some(FoundCrate::Itself) => (None, format_ident!("crate")),
        Some(FoundCrate::Name(name)) => (Some(Default::default()), format_ident!("{}", name)),
        None => (None, format_ident!("iris_ztd")),
    }
}

fn crate_path_fixed() -> Option<FoundCrate> {
    let found_crate = proc_macro_crate::crate_name("iris-ztd").ok()?;

    let ret = match found_crate {
        FoundCrate::Itself => {
            let has_doc_env = std::env::vars().any(|(k, _)| {
                k == "UNSTABLE_RUSTDOC_TEST_LINE" || k == "UNSTABLE_RUSTDOC_TEST_PATH"
            });

            if has_doc_env {
                FoundCrate::Name("iris_ztd".to_string())
            } else {
                FoundCrate::Itself
            }
        }
        x => x,
    };

    Some(ret)
}

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
    let crate_path = get_crate_path();

    let mut generics = input.generics.clone();
    let where_clause = generics.make_where_clause();

    let hash_expr = match &input.data {
        Data::Struct(data) => {
            for field in &data.fields {
                let ty = &field.ty;
                where_clause
                    .predicates
                    .push(syn::parse_quote!(#ty: #crate_path::Hashable));
            }

            match &data.fields {
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
                        let indices: Vec<_> = (0..field_count).map(syn::Index::from).collect();
                        build_nested_tuple_indexed(&indices)
                    }
                }
                Fields::Unit => {
                    quote! { ().hash() }
                }
            }
        }
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

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    TokenStream::from(quote! {
        impl #impl_generics #crate_path::Hashable for #name #ty_generics #where_clause {
            fn hash(&self) -> #crate_path::Digest {
                #hash_expr
            }
        }
    })
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

/// Derive macro for implementing the `NounEncode` trait.
#[proc_macro_derive(NounEncode)]
pub fn derive_noun_encode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let crate_path = get_crate_path();

    let mut generics = input.generics.clone();
    let where_clause = generics.make_where_clause();

    let impl_body = match &input.data {
        Data::Struct(data) => {
            for field in &data.fields {
                let ty = &field.ty;
                where_clause
                    .predicates
                    .push(syn::parse_quote!(#ty: #crate_path::NounEncode));
            }

            match &data.fields {
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

                    if field_names.is_empty() {
                        quote! { #crate_path::NounEncode::to_noun(&0u64) }
                    } else if field_names.len() == 1 {
                        let field = &field_names[0];
                        quote! { #crate_path::NounEncode::to_noun(&self.#field) }
                    } else {
                        let tuple_expr = build_nested_tuple_refs(&field_names);
                        quote! { #crate_path::NounEncode::to_noun(&#tuple_expr) }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_count = fields.unnamed.len();

                    if field_count == 0 {
                        quote! { #crate_path::NounEncode::to_noun(&0u64) }
                    } else if field_count == 1 {
                        quote! { #crate_path::NounEncode::to_noun(&self.0) }
                    } else {
                        let indices: Vec<_> = (0..field_count).map(syn::Index::from).collect();
                        let tuple_expr = build_nested_tuple_refs_indexed(&indices);
                        quote! { #crate_path::NounEncode::to_noun(&#tuple_expr) }
                    }
                }
                Fields::Unit => quote! { #crate_path::NounEncode::to_noun(&0u64) },
            }
        }
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                &input,
                "NounEncode derive macro does not support enums yet",
            )
            .to_compile_error()
            .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &input,
                "NounEncode derive macro does not support unions",
            )
            .to_compile_error()
            .into();
        }
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    TokenStream::from(quote! {
        impl #impl_generics #crate_path::NounEncode for #name #ty_generics #where_clause {
            fn to_noun(&self) -> #crate_path::Noun {
                #impl_body
            }
        }
    })
}

/// Derive macro for implementing the `NounDecode` trait.
#[proc_macro_derive(NounDecode)]
pub fn derive_noun_decode(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;
    let crate_path = get_crate_path();

    let mut generics = input.generics.clone();
    let where_clause = generics.make_where_clause();

    let impl_body = match &input.data {
        Data::Struct(data) => {
            for field in &data.fields {
                let ty = &field.ty;
                where_clause
                    .predicates
                    .push(syn::parse_quote!(#ty: #crate_path::NounDecode));
            }

            match &data.fields {
                Fields::Named(fields) => {
                    let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

                    if field_names.is_empty() {
                        quote! {
                            if noun == #crate_path::noun::atom(0) {
                                Some(Self)
                            } else {
                                None
                            }
                        }
                    } else {
                        quote! {
                            let (#( #field_names ),* ) = #crate_path::NounDecode::from_noun(noun)?;
                            Some(Self {
                                #( #field_names ),*
                            })
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_count = fields.unnamed.len();

                    if field_count == 0 {
                        quote! {
                            if noun == #crate_path::noun::atom(0) {
                                Some(Self)
                            } else {
                                None
                            }
                        }
                    } else if field_count == 1 {
                        quote! { Some(Self(#crate_path::NounDecode::from_noun(noun)?)) }
                    } else {
                        let indices: Vec<_> = (0..field_count).map(syn::Index::from).collect();
                        quote! {
                            let tup = #crate_path::NounDecode::from_noun(noun)?;
                            Some(Self(
                                #( tup.#indices ),*
                            ))
                        }
                    }
                }
                Fields::Unit => quote! {
                    if noun == #crate_path::noun::atom(0) {
                        Some(Self)
                    } else {
                        None
                    }
                },
            }
        }
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                &input,
                "NounDecode derive macro does not support enums yet",
            )
            .to_compile_error()
            .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &input,
                "NounDecode derive macro does not support unions",
            )
            .to_compile_error()
            .into();
        }
    };

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    TokenStream::from(quote! {
        impl #impl_generics #crate_path::NounDecode for #name #ty_generics #where_clause {
            fn from_noun(noun: &#crate_path::Noun) -> Option<Self> {
                #impl_body
            }
        }
    })
}

/// Build nested tuple references: (&self.x, (&self.y, &self.z))
fn build_nested_tuple_refs(field_names: &[&Option<syn::Ident>]) -> proc_macro2::TokenStream {
    let mut iter = field_names.iter().rev();
    let last = iter.next().unwrap();

    let mut result = quote! { &self.#last };

    for field in iter {
        result = quote! { (&self.#field, #result) };
    }

    result
}

/// Build nested tuple references for indices: (&self.0, (&self.1, &self.2))
fn build_nested_tuple_refs_indexed(indices: &[syn::Index]) -> proc_macro2::TokenStream {
    let mut iter = indices.iter().rev();
    let last = iter.next().unwrap();

    let mut result = quote! { &self.#last };

    for index in iter {
        result = quote! { (&self.#index, #result) };
    }

    result
}
