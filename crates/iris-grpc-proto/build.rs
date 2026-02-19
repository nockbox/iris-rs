use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the output directory
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);

    // Use glob pattern to compile all .proto files
    let proto_files: Vec<_> = glob::glob("proto/**/*.proto")?
        .filter_map(Result::ok)
        .collect();

    for proto_file in proto_files.clone() {
        eprintln!("cargo:rerun-if-changed={}", proto_file.display());
        let path_string = proto_file
            .to_str()
            .expect("Couldn't convert proto_file path to string");
        println!("cargo:rerun-if-changed={path_string}");
    }

    let include_dirs = ["proto"].map(PathBuf::from);

    let mut config = tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("nockchain_descriptor.bin"))
        // Add serde derives for all types for WASM interop
        .type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]")
        .type_attribute(".", "#[cfg_attr(feature = \"wasm\", derive(tsify::Tsify))]")
        .type_attribute(
            ".nockchain.public.v2",
            "#[cfg_attr(feature = \"wasm\", tsify(into_wasm_abi, from_wasm_abi, type_prefix = \"PbPub2\"))]")
        .type_attribute(
            ".nockchain.common.v1",
            "#[cfg_attr(feature = \"wasm\", tsify(into_wasm_abi, from_wasm_abi, type_prefix = \"PbCom1\"))]")
        .type_attribute(
            ".nockchain.common.v2",
            "#[cfg_attr(feature = \"wasm\", tsify(into_wasm_abi, from_wasm_abi, type_prefix = \"PbCom2\"))]")
        // Serialize u64 fields as strings to avoid JavaScript MAX_SAFE_INTEGER issues
        .field_attribute(
            "Belt.value",
            "#[serde(with = \"crate::serde_u64_as_string\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "BlockHeight.value",
            "#[serde(with = \"crate::serde_u64_as_string\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "BlockHeightDelta.value",
            "#[serde(with = \"crate::serde_u64_as_string\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "Nicks.value",
            "#[serde(with = \"crate::serde_u64_as_string\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "NoteVersion.value",
            "#[serde(with = \"crate::serde_u32_as_string\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        // Serialize Hash fields as base58 strings for readability
        // NOTE: ALL optional Hash fields must be listed here to ensure consistent serialization
        // NOTE: we do not set CheetahPoint, because we are unsure of the exact scheme to use. Same with SchnorrSignature, as it's a bigint.
        .field_attribute(
            "Name.first",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "Name.last",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "Balance.block_id",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "RawTransaction.id",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "Seed.lock_root",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "Seed.parent_hash",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "PkhSignatureEntry.hash",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        .field_attribute(
            "Source.hash",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        // PkhLock contains repeated Hash - these are serialized as list of hashes
        // MerkleProof.root and .path also contain Hash
        .field_attribute(
            "MerkleProof.root",
            "#[serde(with = \"crate::serde_hash_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string\"))]",
        )
        // Note: repeated Hash fields use the vec serializer
        .field_attribute(
            "PkhLock.hashes",
            "#[serde(with = \"crate::serde_hash_vec_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string[]\"))]",
        )
        .field_attribute(
            "MerkleProof.path",
            "#[serde(with = \"crate::serde_hash_vec_as_base58\")] #[cfg_attr(feature = \"wasm\", tsify(type = \"string[]\"))]",
        );

    // For WASM, we need to disable the transport-based convenience methods
    // since tonic::transport doesn't work in WASM
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        config = config.build_transport(false);
    }

    config.compile_protos(&proto_files, &include_dirs)?;

    // Rewrite generated files to add custom tsify attributes
    rewrite_generated_files(&out_dir)?;

    Ok(())
}

fn rewrite_generated_files(out_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use regex::Regex;
    use std::fs;

    // Helper to capitalize first letter
    fn to_pascal_case(s: &str) -> String {
        s.split('_')
            .map(|part| {
                let mut c = part.chars();
                match c.next() {
                    None => String::new(),
                    Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                }
            })
            .collect()
    }

    // --- Base Regexes (for external vN references) ---
    // Updated to match optional module (none/common/public) before vN
    // Captures:
    // 1: Indent
    // 2: Existing Attr
    // 3: Field Name
    // 4: Super Chain
    // 5: Optional Module (e.g. "common")
    // 6: Version (differs from prev, now separate capture in group)
    // 7: Type Name
    let re_opt = Regex::new(r#"(?m)^(\s*)(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?pub (\w+): ::core::option::Option<((?:super::)+)(?:(\w+)::)?v(\d+)::(\w+)>"#).unwrap();
    let re_vec = Regex::new(r#"(?m)^(\s*)(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?pub (\w+): ::prost::alloc::vec::Vec<((?:super::)+)(?:(\w+)::)?v(\d+)::(\w+)>"#).unwrap();
    let re_plain = Regex::new(r#"(?m)^(\s*)(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?pub (\w+): ((?:super::)+)(?:(\w+)::)?v(\d+)::(\w+)"#).unwrap();

    // Captures:
    // 1: Indent
    // 2: Variant Name
    // 3: Existing Attr
    // 4: Super Chain
    // 5: Optional Module
    // 6: Version
    // 7: Type Name
    let re_enum = Regex::new(r#"(?m)^(\s*)(\w+)\(\s*(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?((?:super::)+)(?:(\w+)::)?v(\d+)::(\w+)\s*\)"#).unwrap();

    // --- Local Regexes (for inner-to-outer references: super::Type) ---
    // Captures:
    // 1: Indent
    // 2: Variant Name
    // 3: Existing Attr
    // 4: Type Name
    let re_enum_local = Regex::new(r#"(?m)^(\s*)(\w+)\(\s*(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?super::(\w+)\s*\)"#).unwrap();

    // --- Nested Module Regexes (for outer-to-inner references: mod::Type) ---
    let re_opt_mod = Regex::new(r#"(?m)^(\s*)(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?pub (\w+): ::core::option::Option<(\w+)::(\w+)>"#).unwrap();
    let re_vec_mod = Regex::new(r#"(?m)^(\s*)(?:(#\[cfg_attr\(feature = "wasm", tsify\(type = "[^"]+"\)\)\])\s*)?pub (\w+): ::prost::alloc::vec::Vec<(\w+)::(\w+)>"#).unwrap();

    // Regex to find the base prefix at the top of the file
    let re_base_prefix = Regex::new(r#"type_prefix = "([^"]+)""#).unwrap();

    // Regex to find nested modules
    let re_mod_start = Regex::new(r#"(?m)^pub mod (\w+) \{$"#).unwrap();

    // Regex to find tsify attributes on structs/enums inside modules to replace prefix
    let re_tsify_prefix = Regex::new(r#"(?m)(type_prefix = ")([^"]+)(")"#).unwrap();

    let entries = fs::read_dir(out_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "rs")
            && path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("nockchain")
        {
            let content = fs::read_to_string(&path)?;
            let mut new_lines = Vec::new();

            // 1. Detect Base Prefix
            let base_prefix = re_base_prefix
                .captures(&content)
                .map(|c| c.get(1).unwrap().as_str().to_string())
                .unwrap_or_else(|| "Pb".to_string());

            // 2. Process line by line for module scoping and prefix rewriting
            let mut current_mod: Option<String> = None;
            let mut brace_depth = 0;
            let mut mod_brace_depth = 0;

            for line in content.lines() {
                // Check for module start
                if let Some(caps) = re_mod_start.captures(line) {
                    current_mod = Some(caps.get(1).unwrap().as_str().to_string());
                    mod_brace_depth = brace_depth;
                }

                let mut modified_line = line.to_string();

                if let Some(mod_name) = &current_mod {
                    if line.contains("type_prefix =") {
                        modified_line = re_tsify_prefix
                            .replace(line, |caps: &regex::Captures| {
                                let prefix = &caps[2];
                                if prefix == base_prefix {
                                    // New Prefix: Base + ModName(Pascal)
                                    let mod_pascal = to_pascal_case(mod_name);
                                    format!(
                                        "{}{}{}",
                                        &caps[1],
                                        format!("{prefix}{mod_pascal}"),
                                        &caps[3]
                                    )
                                } else {
                                    caps[0].to_string()
                                }
                            })
                            .to_string();
                    }
                }

                new_lines.push(modified_line);

                // Update brace depth for state tracking
                let open_braces = line.chars().filter(|c| *c == '{').count();
                let close_braces = line.chars().filter(|c| *c == '}').count();
                brace_depth += open_braces;
                brace_depth -= close_braces;

                if let Some(_) = current_mod {
                    if brace_depth <= mod_brace_depth {
                        current_mod = None;
                    }
                }
            }

            let mut new_content = new_lines.join("\n");

            // 3. Apply Regex Replacements

            // Helper to compute prefix
            let compute_prefix = |mod_name: Option<&str>, ver: &str| -> String {
                match mod_name {
                    Some("common") => format!("PbCom{}", ver),
                    Some("public") => format!("PbPub{}", ver),
                    _ => {
                        // Fallback based on base_prefix
                        if base_prefix.starts_with("PbCom") {
                            format!("PbCom{}", ver)
                        } else {
                            format!("PbPub{}", ver)
                        }
                    }
                }
            };

            // --- External Replacements (vN) ---

            // A. Option
            new_content = re_opt.replace_all(&new_content, |caps: &regex::Captures| {
                if caps.get(2).is_some() { return caps[0].to_string(); }
                let indent = &caps[1];
                let field = &caps[3];
                let super_chain = &caps[4];
                let mod_name = caps.get(5).map(|m| m.as_str());
                let ver = &caps[6];
                let type_name = &caps[7];

                let prefix = compute_prefix(mod_name, ver);

                format!(
                    "{indent}#[cfg_attr(feature = \"wasm\", tsify(type = \"{prefix}{type_name} | undefined\"))]\n{indent}pub {field}: ::core::option::Option<{super_chain}{}v{ver}::{type_name}>",
                    mod_name.map(|m| format!("{}::", m)).unwrap_or_default()
                )
            }).to_string();

            // B. Vec
            new_content = re_vec.replace_all(&new_content, |caps: &regex::Captures| {
                if caps.get(2).is_some() { return caps[0].to_string(); }
                let indent = &caps[1];
                let field = &caps[3];
                let super_chain = &caps[4];
                let mod_name = caps.get(5).map(|m| m.as_str());
                let ver = &caps[6];
                let type_name = &caps[7];

                let prefix = compute_prefix(mod_name, ver);

                format!(
                    "{indent}#[cfg_attr(feature = \"wasm\", tsify(type = \"{prefix}{type_name}[]\"))]\n{indent}pub {field}: ::prost::alloc::vec::Vec<{super_chain}{}v{ver}::{type_name}>",
                    mod_name.map(|m| format!("{}::", m)).unwrap_or_default()
                )
            }).to_string();

            // C. Plain
            new_content = re_plain.replace_all(&new_content, |caps: &regex::Captures| {
                 if caps.get(2).is_some() { return caps[0].to_string(); }
                 let indent = &caps[1];
                 let field = &caps[3];
                 let super_chain = &caps[4];
                 let mod_name = caps.get(5).map(|m| m.as_str());
                 let ver = &caps[6];
                 let type_name = &caps[7];

                 let prefix = compute_prefix(mod_name, ver);

                 format!(
                    "{indent}#[cfg_attr(feature = \"wasm\", tsify(type = \"{prefix}{type_name}\"))]\n{indent}pub {field}: {super_chain}{}v{ver}::{type_name}",
                    mod_name.map(|m| format!("{}::", m)).unwrap_or_default()
                )
            }).to_string();

            // D. Enum
            new_content = re_enum.replace_all(&new_content, |caps: &regex::Captures| {
                 if caps.get(3).is_some() { return caps[0].to_string(); }
                 let indent = &caps[1];
                 let variant = &caps[2];
                 // group 3 is attr
                 let super_chain = &caps[4];
                 let mod_name = caps.get(5).map(|m| m.as_str());
                 let ver = &caps[6];
                 let type_name = &caps[7];

                 let prefix = compute_prefix(mod_name, ver);

                 format!(
                    "{indent}{variant}(#[cfg_attr(feature = \"wasm\", tsify(type = \"{prefix}{type_name}\"))] {super_chain}{}v{ver}::{type_name})",
                    mod_name.map(|m| format!("{}::", m)).unwrap_or_default()
                )
            }).to_string();

            // --- Local Replacements (super::Type) ---

            new_content = re_enum_local.replace_all(&new_content, |caps: &regex::Captures| {
                 if caps.get(3).is_some() { return caps[0].to_string(); }
                 let indent = &caps[1];
                 let variant = &caps[2];
                 let type_name = &caps[4];

                 // If type_name starts with v, ignore (likely v1::Type caught by other regex or just unhandled)
                 if type_name.starts_with('v') && type_name.chars().nth(1).map_or(false, |c| c.is_numeric()) {
                     return caps[0].to_string();
                 }

                 format!(
                    "{indent}{variant}(#[cfg_attr(feature = \"wasm\", tsify(type = \"{base_prefix}{type_name}\"))] super::{type_name})"
                )
            }).to_string();

            // --- Nested Module Replacements (mod::Type) ---

            // Option<mod::Type>
            new_content = re_opt_mod.replace_all(&new_content, |caps: &regex::Captures| {
                if caps.get(2).is_some() { return caps[0].to_string(); }
                let indent = &caps[1];
                let field = &caps[3];
                let mod_name = &caps[4];
                let type_name = &caps[5];

                // Filter out standard modules
                if matches!(mod_name, "super" | "core" | "prost" | "alloc" | "std") {
                    return caps[0].to_string();
                }

                let mod_pascal = to_pascal_case(mod_name);
                let full_type = format!("{base_prefix}{mod_pascal}{type_name}");

                format!(
                    "{indent}#[cfg_attr(feature = \"wasm\", tsify(type = \"{full_type} | undefined\"))]\n{indent}pub {field}: ::core::option::Option<{mod_name}::{type_name}>"
                )
            }).to_string();

            // Vec<mod::Type>
            new_content = re_vec_mod.replace_all(&new_content, |caps: &regex::Captures| {
                if caps.get(2).is_some() { return caps[0].to_string(); }
                let indent = &caps[1];
                let field = &caps[3];
                let mod_name = &caps[4];
                let type_name = &caps[5];

                if matches!(mod_name, "super" | "core" | "prost" | "alloc" | "std") {
                    return caps[0].to_string();
                }

                let mod_pascal = to_pascal_case(mod_name);
                let full_type = format!("{base_prefix}{mod_pascal}{type_name}");

                format!(
                    "{indent}#[cfg_attr(feature = \"wasm\", tsify(type = \"{full_type}[]\"))]\n{indent}pub {field}: ::prost::alloc::vec::Vec<{mod_name}::{type_name}>"
                )
            }).to_string();

            if new_content != content {
                println!("cargo:warning=Rewriting generated file: {}", path.display());
                fs::write(&path, new_content)?;
            }
        }
    }
    Ok(())
}
