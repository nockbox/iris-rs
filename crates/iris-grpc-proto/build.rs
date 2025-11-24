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
        // Serialize u64 fields as strings to avoid JavaScript MAX_SAFE_INTEGER issues
        .field_attribute(
            "Belt.value",
            "#[serde(with = \"crate::serde_u64_as_string\")]",
        )
        .field_attribute(
            "BlockHeight.value",
            "#[serde(with = \"crate::serde_u64_as_string\")]",
        )
        .field_attribute(
            "BlockHeightDelta.value",
            "#[serde(with = \"crate::serde_u64_as_string\")]",
        )
        .field_attribute(
            "Nicks.value",
            "#[serde(with = \"crate::serde_u64_as_string\")]",
        )
        .field_attribute(
            "NoteVersion.value",
            "#[serde(with = \"crate::serde_u32_as_string\")]",
        )
        // Serialize Hash fields as base58 strings for readability
        .field_attribute(
            "Name.first",
            "#[serde(with = \"crate::serde_hash_as_base58\")]",
        )
        .field_attribute(
            "Name.last",
            "#[serde(with = \"crate::serde_hash_as_base58\")]",
        )
        .field_attribute(
            "Balance.block_id",
            "#[serde(with = \"crate::serde_hash_as_base58\")]",
        )
        .field_attribute(
            "RawTransaction.id",
            "#[serde(with = \"crate::serde_hash_as_base58\")]",
        )
        .field_attribute(
            "Seed.lock_root",
            "#[serde(with = \"crate::serde_hash_as_base58\")]",
        )
        .field_attribute(
            "Seed.parent_hash",
            "#[serde(with = \"crate::serde_hash_as_base58\")]",
        );

    // For WASM, we need to disable the transport-based convenience methods
    // since tonic::transport doesn't work in WASM
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32") {
        config = config.build_transport(false);
    }

    config.compile_protos(&proto_files, &include_dirs)?;

    Ok(())
}
