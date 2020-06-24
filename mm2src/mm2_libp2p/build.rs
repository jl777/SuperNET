fn main() {
    prost_build::compile_protos(&["src/p2p_messages.proto"], &["src"]).unwrap();
}