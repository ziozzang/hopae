fn main() {
    tonic_prost_build::configure()
        .skip_debug([".hangang.hopae.v1.ProjectionReply"])
        .compile_protos(&["proto/gateway.proto"], &["proto"])
        .expect("compile gateway gRPC schema");
}
