fn main() {
    tonic_prost_build::compile_protos("proto/gateway.proto").expect("compile gateway gRPC schema");
}
