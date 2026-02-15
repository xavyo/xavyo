fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/ext_authz.proto"], &["proto/"])?;

    println!("cargo:rerun-if-changed=proto/ext_authz.proto");
    Ok(())
}
