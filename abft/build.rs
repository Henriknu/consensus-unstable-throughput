fn main() {
    tonic_build::compile_protos("proto/abft.proto").unwrap();
}
