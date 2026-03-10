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

    let [hash_expr, leaf_expr] = [quote!(hash), quote!(leaf_count)].map(|func| {
        match &input.data {
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
                            quote! { ().#func() }
                        } else if field_names.len() == 1 {
                            // Single field: just hash the field directly
                            let field = &field_names[0];
                            quote! { self.#field.#func() }
                        } else {
                            // Multiple fields: create nested tuples
                            let expr = build_nested_tuple_refs(&field_names);
                            quote! { #expr.#func() }
                        }
                    }
                    Fields::Unnamed(fields) => {
                        let field_count = fields.unnamed.len();

                        if field_count == 0 {
                            quote! { ().#func() }
                        } else if field_count == 1 {
                            quote! { self.0.#func() }
                        } else {
                            // Build nested tuples for tuple structs using indices
                            let indices: Vec<_> = (0..field_count).map(syn::Index::from).collect();
                            let expr = build_nested_tuple_refs_indexed(&indices);
                            quote! { #expr.#func() }
                        }
                    }
                    Fields::Unit => {
                        quote! { ().#func() }
                    }
                }
            }
            Data::Enum(_) => {
                syn::Error::new_spanned(&input, "Hashable derive macro does not support enums yet")
                    .to_compile_error()
            }
            Data::Union(_) => {
                syn::Error::new_spanned(&input, "Hashable derive macro does not support unions")
                    .to_compile_error()
            }
        }
    });

    let pair_expr = match &input.data {
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
                        quote! { ().hashable_pair() }
                    } else if field_names.len() == 1 {
                        // Single field: just hash the field directly
                        let field = &field_names[0];
                        quote! { self.#field.hashable_pair() }
                    } else {
                        // Multiple fields: create nested tuples
                        let expr = build_nested_tuple_refs(&field_names);
                        quote! { Some(#expr) }
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_count = fields.unnamed.len();

                    if field_count == 0 {
                        quote! { ().hashable_pair() }
                    } else if field_count == 1 {
                        quote! { self.0.hashable_pair() }
                    } else {
                        // Build nested tuples for tuple structs using indices
                        let indices: Vec<_> = (0..field_count).map(syn::Index::from).collect();
                        let expr = build_nested_tuple_refs_indexed(&indices);
                        quote! { Some(#expr) }
                    }
                }
                Fields::Unit => {
                    quote! { ().hashable_pair() }
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

            fn leaf_count(&self) -> usize {
                #leaf_expr
            }

            fn hashable_pair(&self) -> Option<(impl #crate_path::Hashable + '_, impl #crate_path::Hashable + '_)> {
                #pair_expr
            }
        }
    })
}

/// Derive macro for implementing the `NounEncode` trait.
#[proc_macro_derive(NounEncode, attributes(noun_tag))]
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
        Data::Enum(data) => {
            let mut match_arms = Vec::new();

            for variant in &data.variants {
                let variant_ident = &variant.ident;
                let mut tag_value = None;

                for attr in &variant.attrs {
                    if attr.path().is_ident("noun_tag") {
                        if let Ok(lit) = attr.parse_args::<syn::LitStr>() {
                            tag_value = Some(lit.value());
                        }
                    }
                }

                let tag_value = tag_value.unwrap_or_else(|| variant_ident.to_string());

                match &variant.fields {
                    Fields::Unit => {
                        match_arms.push(quote! {
                            Self::#variant_ident => #crate_path::NounEncode::to_noun(&#tag_value),
                        });
                    }
                    Fields::Unnamed(fields) => {
                        let field_count = fields.unnamed.len();
                        if field_count == 0 {
                            match_arms.push(quote! {
                                Self::#variant_ident => #crate_path::NounEncode::to_noun(&#tag_value),
                            });
                        } else if field_count == 1 {
                            match_arms.push(quote! {
                                Self::#variant_ident(v0) => {
                                    let tag_noun = #crate_path::NounEncode::to_noun(&#tag_value);
                                    let rest_noun = #crate_path::NounEncode::to_noun(v0);
                                    #crate_path::NounEncode::to_noun(&(tag_noun, rest_noun))
                                }
                            });
                        } else {
                            let idents: Vec<_> =
                                (0..field_count).map(|i| format_ident!("v{}", i)).collect();
                            let ref_idents: Vec<_> = idents.iter().collect();
                            let tuple_expr = build_nested_tuple_expr_for_idents(&ref_idents);
                            match_arms.push(quote! {
                                Self::#variant_ident( #( #idents ),* ) => {
                                    let tag_noun = #crate_path::NounEncode::to_noun(&#tag_value);
                                    let rest_noun = #crate_path::NounEncode::to_noun(&#tuple_expr);
                                    #crate_path::NounEncode::to_noun(&(tag_noun, rest_noun))
                                }
                            });
                        }
                    }
                    Fields::Named(fields) => {
                        let field_names: Vec<_> = fields
                            .named
                            .iter()
                            .map(|f| f.ident.as_ref().unwrap())
                            .collect();
                        if field_names.is_empty() {
                            match_arms.push(quote! {
                                Self::#variant_ident {} => #crate_path::NounEncode::to_noun(&#tag_value),
                            });
                        } else if field_names.len() == 1 {
                            let field = field_names[0];
                            match_arms.push(quote! {
                                Self::#variant_ident { #field } => {
                                    let tag_noun = #crate_path::NounEncode::to_noun(&#tag_value);
                                    let rest_noun = #crate_path::NounEncode::to_noun(#field);
                                    #crate_path::NounEncode::to_noun(&(tag_noun, rest_noun))
                                }
                            });
                        } else {
                            let tuple_expr = build_nested_tuple_expr_for_idents(&field_names);
                            match_arms.push(quote! {
                                Self::#variant_ident { #( #field_names ),* } => {
                                    let tag_noun = #crate_path::NounEncode::to_noun(&#tag_value);
                                    let rest_noun = #crate_path::NounEncode::to_noun(&#tuple_expr);
                                    #crate_path::NounEncode::to_noun(&(tag_noun, rest_noun))
                                }
                            });
                        }
                    }
                }
            }

            quote! {
                match self {
                    #( #match_arms )*
                }
            }
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
#[proc_macro_derive(NounDecode, attributes(noun_tag))]
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
        Data::Enum(data) => {
            let mut cell_match_arms = Vec::new();
            let mut atom_match_arms = Vec::new();

            for variant in &data.variants {
                let variant_ident = &variant.ident;
                let mut tag_value = None;

                for attr in &variant.attrs {
                    if attr.path().is_ident("noun_tag") {
                        if let Ok(lit) = attr.parse_args::<syn::LitStr>() {
                            tag_value = Some(lit.value());
                        }
                    }
                }

                let tag_value = tag_value.unwrap_or_else(|| variant_ident.to_string());

                match &variant.fields {
                    Fields::Unit => {
                        atom_match_arms.push(quote! {
                            #tag_value => Some(Self::#variant_ident),
                        });
                    }
                    Fields::Unnamed(fields) => {
                        let field_count = fields.unnamed.len();
                        if field_count == 0 {
                            atom_match_arms.push(quote! {
                                #tag_value => Some(Self::#variant_ident()),
                            });
                        } else if field_count == 1 {
                            cell_match_arms.push(quote! {
                                #tag_value => {
                                    Some(Self::#variant_ident(#crate_path::NounDecode::from_noun(&rest)?))
                                }
                            });
                        } else {
                            let idents: Vec<_> =
                                (0..field_count).map(|i| format_ident!("v{}", i)).collect();
                            cell_match_arms.push(quote! {
                                #tag_value => {
                                    let ( #( #idents ),* ) = #crate_path::NounDecode::from_noun(&rest)?;
                                    Some(Self::#variant_ident( #( #idents ),* ))
                                }
                            });
                        }
                    }
                    Fields::Named(fields) => {
                        let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();
                        if field_names.is_empty() {
                            atom_match_arms.push(quote! {
                                #tag_value => Some(Self::#variant_ident {}),
                            });
                        } else {
                            cell_match_arms.push(quote! {
                                #tag_value => {
                                    let ( #( #field_names ),* ) = #crate_path::NounDecode::from_noun(&rest)?;
                                    Some(Self::#variant_ident { #( #field_names ),* })
                                }
                            });
                        }
                    }
                }
            }

            quote! {
                match noun {
                    #crate_path::Noun::Atom(atom) => {
                        let a = atom.to_le_bytes();
                        let s = core::str::from_utf8(&a).ok()?;
                        match s {
                            #( #atom_match_arms )*
                            _ => None,
                        }
                    }
                    #crate_path::Noun::Cell(ref a, rest) => {
                        if let #crate_path::Noun::Atom(a) = &**a {
                            let a = a.to_le_bytes();
                            let tag = core::str::from_utf8(&a).ok()?;
                            match tag {
                                #( #cell_match_arms )*
                                _ => None,
                            }
                        } else {
                            None
                        }
                    }
                }
            }
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

/// Build nested tuple expressions for idents used in destructuring: (a, &(b, &c))
fn build_nested_tuple_expr_for_idents(idents: &[&syn::Ident]) -> proc_macro2::TokenStream {
    let mut iter = idents.iter().rev();
    let last = iter.next().unwrap();

    let mut result = quote! { #last };

    for ident in iter {
        result = quote! { (#ident, &#result) };
    }

    result
}

/// Helper to convert PascalCase to snake_case
fn to_snake_case(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.char_indices() {
        if c.is_uppercase() {
            if i > 0 && !s.as_bytes()[i - 1].is_ascii_uppercase() {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Helper to convert PascalCase or snake_case to lowerCamelCase
fn to_lower_camel_case(s: &str) -> String {
    let mut out = String::new();
    let mut capitalize_next = false;
    let mut first = true;
    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if first {
            out.push(c.to_ascii_lowercase());
            first = false;
        } else if capitalize_next {
            out.push(c.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Attribute macro `#[wasm_noun_codec]` to attach tsify attributes and create js codec functions.
/// Supports `#[wasm_noun_codec(no_hash)]` to skip generating the `hash` function.
#[proc_macro_attribute]
pub fn wasm_noun_codec(attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();

    let attr_str = attr.to_string();
    let no_hash = attr_str.contains("no_hash");
    let with_prove = attr_str.contains("with_prove");
    let no_derive = attr_str.contains("no_derive");

    let snake_name = to_snake_case(&name_str);
    let camel_name = to_lower_camel_case(&name_str);

    let to_noun_snake = format_ident!("{}_to_noun", snake_name);
    let from_noun_snake = format_ident!("{}_from_noun", snake_name);
    let hash_snake = format_ident!("{}_hash", snake_name);
    let prove_snake = format_ident!("{}_prove", snake_name);

    let to_noun_camel = format!("{}ToNoun", camel_name);
    let from_noun_camel = format!("{}FromNoun", camel_name);
    let hash_camel = format!("{}Hash", camel_name);
    let prove_camel = format!("{}Prove", camel_name);

    let mod_name = format_ident!("__wasm_noun_codec_{}", snake_name);

    let crate_path = get_crate_path();

    let derive_attrs = if no_derive {
        quote! {}
    } else {
        quote! {
            #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
            #[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
        }
    };

    let hash_fn = if no_hash {
        quote! {}
    } else {
        quote! {
            #[wasm_bindgen(js_name = #hash_camel)]
            pub fn #hash_snake(v: &#name) -> #crate_path::Digest {
                #crate_path::Hashable::hash(v)
            }
        }
    };

    let prove_fn = if with_prove {
        quote! {
            /// Create a 0-indexed merkle proof for the type's subleaf.
            ///
            /// Note that unlike `prove-hashable-by-index:merkle`, which is 1-indexed, this method is 0-indexed.
            #[wasm_bindgen(js_name = #prove_camel)]
            pub fn #prove_snake(v: &#name, leaf_index: u32) -> #crate_path::MerkleProvenAxis {
                #crate_path::MerkleProof::prove_hashable(v, leaf_index as usize)
            }
        }
    } else {
        quote! {}
    };

    let expanded = quote! {
        #derive_attrs
        #input

        #[cfg(feature = "wasm")]
        mod #mod_name {
            use super::*;
            use wasm_bindgen::prelude::*;

            /// Convert into `Noun`.
            #[wasm_bindgen(js_name = #to_noun_camel)]
            pub fn #to_noun_snake(v: &#name) -> #crate_path::Noun {
                #crate_path::NounEncode::to_noun(v)
            }

            /// Convert from `Noun`.
            #[wasm_bindgen(js_name = #from_noun_camel)]
            pub fn #from_noun_snake(noun: &#crate_path::Noun) -> ::core::result::Result<#name, JsValue> {
                #crate_path::NounDecode::from_noun(noun)
                    .ok_or_else(|| JsValue::from_str("Failed to decode noun"))
            }

            #hash_fn
            #prove_fn
        }
    };

    TokenStream::from(expanded)
}

/// Extract signatures from an `impl` block and generate corresponding
/// `wasm_bindgen` exported functions within a private `cfg(feature = "wasm")` submodule.
#[proc_macro_attribute]
pub fn wasm_member_methods(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as syn::ItemImpl);

    // Determine target type name
    let ty = &input.self_ty;
    let type_name = if let syn::Type::Path(type_path) = &**ty {
        if let Some(segment) = type_path.path.segments.last() {
            segment.ident.to_string()
        } else {
            return syn::Error::new_spanned(ty, "Expected a type path")
                .to_compile_error()
                .into();
        }
    } else {
        return syn::Error::new_spanned(ty, "Expected a type path")
            .to_compile_error()
            .into();
    };

    let snake_name = to_snake_case(&type_name);
    let mod_name = format_ident!("__wasm_member_methods_{}", snake_name);

    let mut generated_methods = Vec::new();

    for item in &mut input.items {
        if let syn::ImplItem::Fn(method) = item {
            // Check visibility (only export pub methods)
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                continue;
            }

            let sig = &method.sig;
            let method_ident = &sig.ident;
            let method_name_str = method_ident.to_string();

            // Extract attributes, looking for transform_output
            let mut transform_output: Option<(syn::Type, syn::Expr)> = None;

            method.attrs.retain(|attr| {
                if attr.path().is_ident("transform_output") {
                    // Parse #[transform_output(Type, expr)]
                    if let syn::Meta::List(meta_list) = &attr.meta {
                        let tokens: Vec<_> = meta_list.tokens.clone().into_iter().collect();

                        let mut ty_tokens = proc_macro2::TokenStream::new();
                        let mut expr_tokens = proc_macro2::TokenStream::new();
                        let mut in_ty = true;

                        for t in tokens {
                            if in_ty {
                                if let proc_macro2::TokenTree::Punct(ref p) = t {
                                    if p.as_char() == ',' {
                                        in_ty = false;
                                        continue;
                                    }
                                }
                                ty_tokens.extend(std::iter::once(t));
                            } else {
                                expr_tokens.extend(std::iter::once(t));
                            }
                        }

                        // Parse safely, fallback if fails
                        if let Ok(ty) = syn::parse2(ty_tokens) {
                            if let Ok(expr) = syn::parse2(expr_tokens) {
                                transform_output = Some((ty, expr));
                            }
                        }
                    }
                    false // Remove this attribute
                } else {
                    true // Keep others
                }
            });

            let camel_method_name = to_lower_camel_case(&method_name_str);
            let struct_camel = to_lower_camel_case(&type_name);
            let camel_method_capitalized = {
                let mut c = camel_method_name.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                }
            };
            let js_name_combined = format!("{}{}", struct_camel, camel_method_capitalized);
            let js_name_attr =
                quote! { #[wasm_bindgen::prelude::wasm_bindgen(js_name = #js_name_combined)] };

            // Extract doc comments
            let doc_comments: Vec<_> = method
                .attrs
                .iter()
                .filter(|a| a.path().is_ident("doc"))
                .collect();

            let mut args = Vec::new();
            let mut pass_args = Vec::new();
            let mut has_receiver = false;

            for arg in &sig.inputs {
                match arg {
                    syn::FnArg::Receiver(r) => {
                        has_receiver = true;
                        let mutf = r.mutability;
                        // Use the parsed `ty` instead of the string `type_name`
                        if r.reference.is_some() {
                            if mutf.is_some() {
                                args.push(quote! { obj: &mut #ty });
                            } else {
                                args.push(quote! { obj: &#ty });
                            }
                        } else {
                            args.push(quote! { obj: #ty });
                        }
                    }
                    syn::FnArg::Typed(pat_type) => {
                        let pat = &pat_type.pat;
                        let pt_ty = &pat_type.ty;
                        args.push(quote! { #pat: #pt_ty });
                        pass_args.push(quote! { #pat });
                    }
                }
            }

            let call_expr = if has_receiver {
                quote! { obj.#method_ident(#(#pass_args),*) }
            } else {
                quote! { <#ty>::#method_ident(#(#pass_args),*) }
            };

            let (final_output, body) =
                if let Some((transform_ty, transform_expr)) = transform_output {
                    let out = quote! { -> #transform_ty };
                    let b = quote! {
                        let out = #call_expr;
                        #transform_expr
                    };
                    (out, b)
                } else {
                    let mut output = sig.output.clone();
                    // Replace `Self` with the actual type name in the return type
                    if let syn::ReturnType::Type(_, ret_ty) = &mut output {
                        if let syn::Type::Path(type_path) = &mut **ret_ty {
                            if type_path.path.is_ident("Self") {
                                **ret_ty = *(*ty).clone();
                            }
                        }
                    }
                    let out = quote! { #output };
                    let b = quote! { #call_expr };
                    (out, b)
                };

            generated_methods.push(quote! {
                #(#doc_comments)*
                #js_name_attr
                pub fn #method_ident(#(#args),*) #final_output {
                    #body
                }
            });
        }
    }

    let expanded = quote! {
        #input

        #[cfg(feature = "wasm")]
        #[allow(non_snake_case)]
        mod #mod_name {
            use super::*;

            #(#generated_methods)*
        }
    };

    TokenStream::from(expanded)
}

/// Attribute macro `#[noun_derive(NounEncode, NounDecode, Hashable, Serialize, Deserialize)]`
///
/// Supports `#[noun(cell)]` and `#[noun(tag = N)]` on enum variants.
/// Generates NounEncode/NounDecode/Hashable impls, and serde shadow types for Serialize/Deserialize.
#[proc_macro_attribute]
pub fn noun_derive(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(item as syn::ItemEnum);
    let crate_path = get_crate_path();
    let enum_name = &input.ident;
    let vis = &input.vis;

    // Parse attribute args: comma-separated idents like NounEncode, NounDecode, Hashable, Serialize, Deserialize
    let attr_args = proc_macro2::TokenStream::from(attr);
    let requested_derives: Vec<String> = attr_args
        .into_iter()
        .filter_map(|tt| {
            if let proc_macro2::TokenTree::Ident(ident) = tt {
                Some(ident.to_string())
            } else {
                None
            }
        })
        .collect();

    let wants_noun_encode = requested_derives.iter().any(|s| s == "NounEncode");
    let wants_noun_decode = requested_derives.iter().any(|s| s == "NounDecode");
    let wants_hashable = requested_derives.iter().any(|s| s == "Hashable");
    let wants_serialize = requested_derives.iter().any(|s| s == "Serialize");
    let wants_deserialize = requested_derives.iter().any(|s| s == "Deserialize");
    let wants_wasm = requested_derives.iter().any(|s| s == "tsify_wasm");

    // Collect passthrough derives (everything other than the ones we handle manually)
    let handled = [
        "NounEncode",
        "NounDecode",
        "Hashable",
        "Serialize",
        "Deserialize",
        "tsify_wasm",
    ];
    let passthrough_derives: Vec<proc_macro2::TokenStream> = requested_derives
        .iter()
        .filter(|s| !handled.contains(&s.as_str()))
        .map(|s| {
            let ident = format_ident!("{}", s);
            quote! { #ident }
        })
        .collect();

    // --- Parse #[noun(...)] attributes on enum ---
    let mut tag_ident = format_ident!("tag");
    input.attrs.retain(|attr| {
        if !attr.path().is_ident("noun") {
            return true;
        }
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("tag_ident") {
                if let Ok(value) = meta.value() {
                    if let Ok(ident) = value.parse::<syn::Ident>() {
                        tag_ident = ident;
                    }
                }
            }
            Ok(())
        });
        false
    });

    // --- Parse #[noun(...)] attributes on each variant ---
    enum NounVariantKind {
        Cell,           // #[noun(cell)]
        TagU64(u64),    // #[noun(tag = 123)]
        TagStr(String), // #[noun(tag = "foo")]
    }

    struct VariantInfo {
        ident: syn::Ident,
        kind: NounVariantKind,
        fields: syn::Fields,
    }

    let mut variants_info = Vec::new();
    let mut cell_count = 0;

    for variant in &mut input.variants {
        let mut kind = None;

        variant.attrs.retain(|attr| {
            if !attr.path().is_ident("noun") {
                return true;
            }
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("cell") {
                    kind = Some(NounVariantKind::Cell);
                    cell_count += 1;
                } else if meta.path.is_ident("tag") {
                    let value = meta.value().expect("noun(tag = ...) requires a value");
                    let lit: syn::Lit = value.parse().expect("tag value must be a literal");
                    match lit {
                        syn::Lit::Int(lit_int) => {
                            let v: u64 = lit_int.base10_parse().expect("tag must be u64");
                            kind = Some(NounVariantKind::TagU64(v));
                        }
                        syn::Lit::Str(lit_str) => {
                            kind = Some(NounVariantKind::TagStr(lit_str.value()));
                        }
                        _ => panic!("noun(tag = ...) value must be an integer or string literal"),
                    }
                }
                Ok(())
            });
            false // strip the #[noun(...)] attribute
        });

        let kind = kind.unwrap_or_else(|| NounVariantKind::TagStr(variant.ident.to_string()));

        variants_info.push(VariantInfo {
            ident: variant.ident.clone(),
            kind,
            fields: variant.fields.clone(),
        });
    }

    if cell_count > 1 {
        panic!("Only one #[noun(cell)] variant is allowed per enum");
    }

    // --- Generate NounEncode ---
    let noun_encode_impl = if wants_noun_encode {
        let mut arms = Vec::new();
        for vi in &variants_info {
            let vident = &vi.ident;
            match &vi.kind {
                NounVariantKind::Cell => {
                    // Encode inner value directly
                    match &vi.fields {
                        Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                            arms.push(quote! {
                                Self::#vident(v) => #crate_path::NounEncode::to_noun(v),
                            });
                        }
                        _ => panic!("noun(cell) variant must have exactly one unnamed field"),
                    }
                }
                NounVariantKind::TagU64(tag) => match &vi.fields {
                    Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                        arms.push(quote! {
                            Self::#vident(v) => {
                                let tag_noun = #crate_path::NounEncode::to_noun(&(#tag as u64));
                                let rest_noun = #crate_path::NounEncode::to_noun(v);
                                #crate_path::NounEncode::to_noun(&(tag_noun, rest_noun))
                            }
                        });
                    }
                    Fields::Unit => {
                        arms.push(quote! {
                            Self::#vident => #crate_path::NounEncode::to_noun(&(#tag as u64)),
                        });
                    }
                    _ => panic!("noun(tag = N) variant must have 0 or 1 unnamed field"),
                },
                NounVariantKind::TagStr(tag) => match &vi.fields {
                    Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                        arms.push(quote! {
                            Self::#vident(v) => {
                                let tag_noun = #crate_path::NounEncode::to_noun(&#tag);
                                let rest_noun = #crate_path::NounEncode::to_noun(v);
                                #crate_path::NounEncode::to_noun(&(tag_noun, rest_noun))
                            }
                        });
                    }
                    Fields::Unit => {
                        arms.push(quote! {
                            Self::#vident => #crate_path::NounEncode::to_noun(&#tag),
                        });
                    }
                    _ => panic!("noun(tag = \"str\") variant must have 0 or 1 unnamed field"),
                },
            }
        }
        quote! {
            impl #crate_path::NounEncode for #enum_name {
                fn to_noun(&self) -> #crate_path::Noun {
                    match self {
                        #(#arms)*
                    }
                }
            }
        }
    } else {
        quote! {}
    };

    // --- Generate NounDecode ---
    let noun_decode_impl = if wants_noun_decode {
        // Find the cell variant (if any)
        let cell_variant = variants_info
            .iter()
            .find(|v| matches!(v.kind, NounVariantKind::Cell));

        let cell_fallback = if let Some(cv) = cell_variant {
            let cv_ident = &cv.ident;
            quote! {
                // Tag is not an atom (it's a cell), try the cell variant
                return Some(Self::#cv_ident(#crate_path::NounDecode::from_noun(noun)?));
            }
        } else {
            quote! { return None; }
        };

        // Build match arms for u64 tags
        let mut u64_tag_arms = Vec::new();
        for vi in &variants_info {
            if let NounVariantKind::TagU64(tag) = &vi.kind {
                let vident = &vi.ident;
                match &vi.fields {
                    Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                        u64_tag_arms.push(quote! {
                            #tag => return Some(Self::#vident(#crate_path::NounDecode::from_noun(rest)?)),
                        });
                    }
                    Fields::Unit => {
                        u64_tag_arms.push(quote! {
                            #tag => return Some(Self::#vident),
                        });
                    }
                    _ => {}
                }
            }
        }

        // Build match arms for string tags
        let mut str_tag_arms = Vec::new();
        for vi in &variants_info {
            if let NounVariantKind::TagStr(tag) = &vi.kind {
                let vident = &vi.ident;
                match &vi.fields {
                    Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                        str_tag_arms.push(quote! {
                            #tag => return Some(Self::#vident(#crate_path::NounDecode::from_noun(rest)?)),
                        });
                    }
                    Fields::Unit => {
                        str_tag_arms.push(quote! {
                            #tag => return Some(Self::#vident),
                        });
                    }
                    _ => {}
                }
            }
        }

        let has_u64_tags = !u64_tag_arms.is_empty();
        let has_str_tags = !str_tag_arms.is_empty();

        let u64_match_block = if has_u64_tags {
            quote! {
                if let Some(tag_u64) = <u64 as #crate_path::NounDecode>::from_noun(tag_noun) {
                    match tag_u64 {
                        #(#u64_tag_arms)*
                        _ => {}
                    }
                }
            }
        } else {
            quote! {}
        };

        let str_match_block = if has_str_tags {
            quote! {
                {
                    let a_bytes = tag_atom.to_le_bytes();
                    if let Ok(tag_str) = core::str::from_utf8(&a_bytes) {
                        match tag_str {
                            #(#str_tag_arms)*
                            _ => {}
                        }
                    }
                }
            }
        } else {
            quote! {}
        };

        quote! {
            impl #crate_path::NounDecode for #enum_name {
                fn from_noun(noun: &#crate_path::Noun) -> Option<Self> {
                    match noun {
                        #crate_path::Noun::Cell(ref tag_noun, ref rest) => {
                            // Check if tag is an atom
                            if let #crate_path::Noun::Atom(ref tag_atom) = **tag_noun {
                                // Try u64 tag matching
                                #u64_match_block
                                // Try string tag matching
                                #str_match_block
                                // No tag matched
                                None
                            } else {
                                // Tag is not an atom (it's a cell) => try cell variant
                                #cell_fallback
                            }
                        }
                        #crate_path::Noun::Atom(_) => {
                            // Atom at top level - try cell variant as fallback
                            #cell_fallback
                        }
                    }
                }
            }
        }
    } else {
        quote! {}
    };

    // --- Generate Hashable ---
    let hashable_impl = if wants_hashable {
        let mut arms_hash = Vec::new();
        let mut arms_leaves = Vec::new();
        let mut arms_pairs = Vec::new();
        let mut eithers = vec![];
        for (i, vi) in variants_info.iter().enumerate() {
            let vident = &vi.ident;
            let cur_eithers = if i == variants_info.len() - 1 {
                eithers.clone()
            } else {
                [&eithers[..], &[quote!(#crate_path::Either::Left)][..]].concat()
            };
            let nest = |a: proc_macro2::TokenStream| {
                cur_eithers.iter().rev().fold(a, |acc, f| quote!(#f(#acc)))
            };
            match &vi.kind {
                NounVariantKind::Cell => match &vi.fields {
                    Fields::Unnamed(_) => {
                        arms_hash.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::hash(v),
                        });
                        arms_leaves.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::leaf_count(v),
                        });
                        let nested_a = nest(quote!(a));
                        let nested_b = nest(quote!(b));
                        arms_pairs.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::hashable_pair(v).map(|(a, b)| (#nested_a, #nested_b)),
                        });
                    }
                    Fields::Unit => {
                        arms_hash.push(quote! {
                            Self::#vident => #crate_path::Hashable::hash(&0u64),
                        });
                        arms_leaves.push(quote! {
                            Self::#vident => #crate_path::Hashable::leaf_count(&0u64),
                        });
                        let nested_a = nest(quote!(a));
                        let nested_b = nest(quote!(b));
                        arms_pairs.push(quote! {
                            Self::#vident => Option::<((),())>::None.map(|(a, b)| (#nested_a, #nested_b)),
                        });
                    }
                    _ => {}
                },
                NounVariantKind::TagU64(tag) => match &vi.fields {
                    Fields::Unnamed(_) => {
                        arms_hash.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::hash(&(#tag as u64, v)),
                        });
                        arms_leaves.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::leaf_count(&(#tag as u64, v)),
                        });
                        let nested_tag = nest(quote!(#tag as u64));
                        let nested_value = nest(quote!(v));
                        arms_pairs.push(quote! {
                            Self::#vident(v) => Some((#nested_tag, #nested_value)),
                        });
                    }
                    Fields::Unit => {
                        arms_hash.push(quote! {
                            Self::#vident => #crate_path::Hashable::hash(&(#tag as u64)),
                        });
                        arms_leaves.push(quote! {
                            Self::#vident => #crate_path::Hashable::leaf_count(&(#tag as u64)),
                        });
                        let nested_a = nest(quote!(a));
                        let nested_b = nest(quote!(b));
                        arms_pairs.push(quote! {
                            Self::#vident => Option::<((),())>::None.map(|(a, b)| (#nested_a, #nested_b)),
                        });
                    }
                    _ => {}
                },
                NounVariantKind::TagStr(tag) => match &vi.fields {
                    Fields::Unnamed(_) => {
                        arms_hash.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::hash(&(#tag, v)),
                        });
                        arms_leaves.push(quote! {
                            Self::#vident(v) => #crate_path::Hashable::leaf_count(&(#tag, v)),
                        });
                        let nested_tag = nest(quote!(#tag));
                        let nested_value = nest(quote!(v));
                        arms_pairs.push(quote! {
                            Self::#vident(v) => Some((#nested_tag, #nested_value)),
                        });
                    }
                    Fields::Unit => {
                        arms_hash.push(quote! {
                            Self::#vident => #crate_path::Hashable::hash(&#tag),
                        });
                        arms_leaves.push(quote! {
                            Self::#vident => #crate_path::Hashable::leaf_count(&#tag),
                        });
                        let nested_a = nest(quote!(a));
                        let nested_b = nest(quote!(b));
                        arms_pairs.push(quote! {
                            Self::#vident => Option::<((),())>::None.map(|(a, b)| (#nested_a, #nested_b)),
                        });
                    }
                    _ => {}
                },
            }
            eithers.push(quote!(#crate_path::Either::Right));
        }
        quote! {
            impl #crate_path::Hashable for #enum_name {
                fn hash(&self) -> #crate_path::Digest {
                    match self {
                        #(#arms_hash)*
                    }
                }

                fn leaf_count(&self) -> usize {
                    match self {
                        #(#arms_leaves)*
                    }
                }

                fn hashable_pair<'a>(&'a self) -> Option<(impl #crate_path::Hashable + 'a, impl #crate_path::Hashable + 'a)> {
                    match self {
                        #(#arms_pairs)*
                    }
                }
            }
        }
    } else {
        quote! {}
    };

    // --- Generate Shadow Types & Serde ---
    let serde_impl = if wants_serialize || wants_deserialize {
        let shadow_mod_name = format_ident!(
            "__noun_derive_shadow_{}",
            to_snake_case(&enum_name.to_string())
        );
        let shadow_owned_name = enum_name.clone();
        let shadow_borrowed_name = format_ident!("__ShadowBorrowed{}", enum_name);

        // Build shadow owned variants
        let mut shadow_owned_variants = Vec::new();
        let mut shadow_borrowed_variants = Vec::new();
        let mut from_shadow_arms = Vec::new(); // ShadowOwned -> Enum
        let mut to_shadow_owned_arms = Vec::new(); // Enum -> ShadowOwned
        let mut into_shadow_arms = Vec::new(); // &Enum -> ShadowBorrowed

        for vi in &variants_info {
            let vident = &vi.ident;
            match &vi.kind {
                NounVariantKind::Cell => {
                    // Untagged: transparent
                    match &vi.fields {
                        Fields::Unnamed(f) => {
                            let inner_ty = &f.unnamed[0].ty;
                            shadow_owned_variants.push(quote! {
                                #vident(#inner_ty),
                            });
                            shadow_borrowed_variants.push(quote! {
                                #vident(&'a #inner_ty),
                            });
                            from_shadow_arms.push(quote! {
                                #shadow_owned_name::#vident(v) => super::#enum_name::#vident(v),
                            });
                            to_shadow_owned_arms.push(quote! {
                                super::#enum_name::#vident(v) => #shadow_owned_name::#vident(v),
                            });
                            into_shadow_arms.push(quote! {
                                super::#enum_name::#vident(ref v) => #shadow_borrowed_name::#vident(v),
                            });
                        }
                        _ => panic!("noun(cell) variant must have unnamed fields"),
                    }
                }
                NounVariantKind::TagU64(tag) => {
                    let tag_str = tag.to_string();
                    match &vi.fields {
                        Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                            let inner_ty = &f.unnamed[0].ty;
                            shadow_owned_variants.push(quote! {
                                #vident {
                                    #[cfg_attr(feature = "wasm", tsify(type = #tag_str))]
                                    #tag_ident: u64,
                                    #[serde(flatten)]
                                    value: #inner_ty,
                                },
                            });
                            shadow_borrowed_variants.push(quote! {
                                #vident {
                                    #tag_ident: u64,
                                    #[serde(flatten)]
                                    value: &'a #inner_ty,
                                },
                            });
                            from_shadow_arms.push(quote! {
                                #shadow_owned_name::#vident { value, .. } => super::#enum_name::#vident(value),
                            });
                            to_shadow_owned_arms.push(quote! {
                                super::#enum_name::#vident(v) => #shadow_owned_name::#vident { #tag_ident: #tag, value: v },
                            });
                            into_shadow_arms.push(quote! {
                                super::#enum_name::#vident(ref v) => #shadow_borrowed_name::#vident { #tag_ident: #tag, value: v },
                            });
                        }
                        Fields::Unit => {
                            shadow_owned_variants.push(quote! {
                                #vident {
                                    #[cfg_attr(feature = "wasm", tsify(type = #tag_str))]
                                    #tag_ident: u64
                                },
                            });
                            shadow_borrowed_variants.push(quote! {
                                #vident { #tag_ident: u64 },
                            });
                            from_shadow_arms.push(quote! {
                                #shadow_owned_name::#vident { .. } => super::#enum_name::#vident,
                            });
                            to_shadow_owned_arms.push(quote! {
                                super::#enum_name::#vident => #shadow_owned_name::#vident { #tag_ident: #tag },
                            });
                            into_shadow_arms.push(quote! {
                                super::#enum_name::#vident => #shadow_borrowed_name::#vident { #tag_ident: #tag },
                            });
                        }
                        _ => panic!("noun(tag = N) variant must have 0 or 1 unnamed field"),
                    }
                }
                NounVariantKind::TagStr(tag) => {
                    let tag_str = format!("\"{}\"", tag);
                    match &vi.fields {
                        Fields::Unnamed(f) if f.unnamed.len() == 1 => {
                            let inner_ty = &f.unnamed[0].ty;
                            shadow_owned_variants.push(quote! {
                                #vident {
                                    #[cfg_attr(feature = "wasm", tsify(type = #tag_str))]
                                    #tag_ident: alloc::string::String,
                                    #[serde(flatten)]
                                    value: #inner_ty,
                                },
                            });
                            shadow_borrowed_variants.push(quote! {
                                #vident {
                                    #tag_ident: &'a str,
                                    #[serde(flatten)]
                                    value: &'a #inner_ty,
                                },
                            });
                            from_shadow_arms.push(quote! {
                                #shadow_owned_name::#vident { value, .. } => super::#enum_name::#vident(value),
                            });
                            to_shadow_owned_arms.push(quote! {
                                super::#enum_name::#vident(v) => #shadow_owned_name::#vident { #tag_ident: #tag.into(), value: v },
                            });
                            into_shadow_arms.push(quote! {
                                super::#enum_name::#vident(ref v) => #shadow_borrowed_name::#vident { #tag_ident: #tag, value: v },
                            });
                        }
                        Fields::Unit => {
                            shadow_owned_variants.push(quote! {
                                #vident {
                                    #[cfg_attr(feature = "wasm", tsify(type = #tag_str))]
                                    #tag_ident: alloc::string::String
                                },
                            });
                            shadow_borrowed_variants.push(quote! {
                                #vident { #tag_ident: &'a str },
                            });
                            from_shadow_arms.push(quote! {
                                #shadow_owned_name::#vident { .. } => super::#enum_name::#vident,
                            });
                            to_shadow_owned_arms.push(quote! {
                                super::#enum_name::#vident => #shadow_owned_name::#vident { #tag_ident: #tag.into() },
                            });
                            into_shadow_arms.push(quote! {
                                super::#enum_name::#vident => #shadow_borrowed_name::#vident { #tag_ident: #tag },
                            });
                        }
                        _ => panic!("noun(tag = \"str\") variant must have 0 or 1 unnamed field"),
                    }
                }
            }
        }

        let serialize_impl = if wants_serialize {
            quote! {
                impl serde::Serialize for #enum_name {
                    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
                    where
                        S: serde::Serializer,
                    {
                        let shadow: #shadow_mod_name::#shadow_borrowed_name = self.into();
                        shadow.serialize(serializer)
                    }
                }
            }
        } else {
            quote! {}
        };

        let deserialize_impl = if wants_deserialize {
            quote! {
                impl<'de> serde::Deserialize<'de> for #enum_name {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: serde::Deserializer<'de>,
                    {
                        let shadow = #shadow_mod_name::#shadow_owned_name::deserialize(deserializer)?;
                        Ok(shadow.into())
                    }
                }
            }
        } else {
            quote! {}
        };

        let wasm_impl = if wants_wasm {
            quote! {
                #[cfg(feature = "wasm")]
                const _: () = {
                use tsify::Tsify;
                use wasm_bindgen::JsValue;
                use wasm_bindgen::convert::*;
                use wasm_bindgen::describe::*;
                use wasm_bindgen::UnwrapThrowExt;

                impl Tsify for #enum_name {
                    type JsType = <#shadow_mod_name::#shadow_owned_name as Tsify>::JsType;
                    const DECL: &'static str = <#shadow_mod_name::#shadow_owned_name as Tsify>::DECL;
                }

                impl WasmDescribe for #enum_name {
                    #[inline]
                    fn describe() {
                        <#shadow_mod_name::#shadow_owned_name as WasmDescribe>::describe()
                    }
                }

                #[automatically_derived]
                impl WasmDescribeVector for #enum_name {
                    #[inline]
                    fn describe_vector() {
                        <#shadow_mod_name::#shadow_owned_name as WasmDescribeVector>::describe_vector()
                    }
                }

                impl IntoWasmAbi for #enum_name {
                    type Abi = <#shadow_mod_name::#shadow_owned_name as IntoWasmAbi>::Abi;

                    #[inline]
                    fn into_abi(self) -> Self::Abi {
                        let shadow: #shadow_mod_name::#shadow_owned_name = self.into();
                        shadow.into_abi()
                    }
                }

                impl FromWasmAbi for #enum_name {
                    type Abi = <#shadow_mod_name::#shadow_owned_name as FromWasmAbi>::Abi;

                    #[inline]
                    unsafe fn from_abi(js: Self::Abi) -> Self {
                        let shadow = <#shadow_mod_name::#shadow_owned_name as FromWasmAbi>::from_abi(js);
                        shadow.into()
                    }
                }

                #[automatically_derived]
                impl OptionFromWasmAbi for #enum_name {
                    #[inline]
                    fn is_none(js: &Self::Abi) -> bool {
                        <<Self as Tsify>::JsType as OptionFromWasmAbi>::is_none(js)
                    }
                }

                pub struct SelfOwner<T>(T);

                #[automatically_derived]
                impl<T> ::core::ops::Deref for SelfOwner<T> {
                    type Target = T;

                    fn deref(&self) -> &Self::Target {
                        &self.0
                    }
                }

                impl RefFromWasmAbi for #enum_name {
                    type Abi = <<Self as Tsify>::JsType as RefFromWasmAbi>::Abi;

                    type Anchor = SelfOwner<Self>;

                    unsafe fn ref_from_abi(js: Self::Abi) -> Self::Anchor {
                        let result = <Self as Tsify>::from_js(&*<<Self as Tsify>::JsType as RefFromWasmAbi>::ref_from_abi(js));
                        if let Err(err) = result {
                            wasm_bindgen::throw_str(err.to_string().as_ref());
                        }
                        SelfOwner(result.unwrap_throw())
                    }
                }

                #[automatically_derived]
                impl VectorFromWasmAbi for #enum_name {
                    type Abi = <<Self as Tsify>::JsType as VectorFromWasmAbi>::Abi;

                    #[inline]
                    unsafe fn vector_from_abi(js: Self::Abi) -> Box<[Self]> {
                        <<Self as Tsify>::JsType as VectorFromWasmAbi>::vector_from_abi(js)
                            .into_iter()
                            .map(|value| {
                                let result = Self::from_js(value);
                                if let Err(err) = result {
                                    wasm_bindgen::throw_str(err.to_string().as_ref());
                                }
                                result.unwrap_throw()
                            })
                            .collect()
                    }
                }
                };
            }
        } else {
            quote! {}
        };

        quote! {
            #[allow(non_snake_case)]
            mod #shadow_mod_name {
                use super::*;

                #[derive(serde::Serialize, serde::Deserialize)]
                #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
                #[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
                #[serde(untagged)]
                pub enum #shadow_owned_name {
                    #(#shadow_owned_variants)*
                }

                #[derive(serde::Serialize)]
                #[serde(untagged)]
                pub enum #shadow_borrowed_name<'a> {
                    #(#shadow_borrowed_variants)*
                }

                impl From<#shadow_owned_name> for super::#enum_name {
                    fn from(shadow: #shadow_owned_name) -> Self {
                        match shadow {
                            #(#from_shadow_arms)*
                        }
                    }
                }

                impl From<super::#enum_name> for #shadow_owned_name {
                    fn from(val: super::#enum_name) -> Self {
                        match val {
                            #(#to_shadow_owned_arms)*
                        }
                    }
                }

                impl<'a> From<&'a super::#enum_name> for #shadow_borrowed_name<'a> {
                    fn from(val: &'a super::#enum_name) -> Self {
                        match val {
                            #(#into_shadow_arms)*
                        }
                    }
                }
            }

            #serialize_impl
            #deserialize_impl
            #wasm_impl
        }
    } else {
        quote! {}
    };

    // --- Build the output ---
    // Add passthrough derives to the original enum
    let passthrough_derive_attr = if !passthrough_derives.is_empty() {
        quote! { #[derive(#(#passthrough_derives),*)] }
    } else {
        quote! {}
    };

    let variants = &input.variants;
    let original_attrs = &input.attrs;

    let expanded = quote! {
        #(#original_attrs)*
        #passthrough_derive_attr
        #vis enum #enum_name {
            #variants
        }

        #noun_encode_impl
        #noun_decode_impl
        #hashable_impl
        #serde_impl
    };

    TokenStream::from(expanded)
}
