fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["proto/messenger.proto"], // Input .proto file
            &["proto"],                 // Include path for imports
        )?;
    Ok(())
}
