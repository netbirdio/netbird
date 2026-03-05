fn main() {
    // Compile the daemon.proto for tonic gRPC client
    tonic_build::compile_protos("../../proto/daemon.proto")
        .expect("Failed to compile daemon.proto");

    tauri_build::build();
}
