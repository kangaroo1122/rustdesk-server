fn main() {
    hbb_common::gen_version();
    println!("cargo:rerun-if-changed=protos/rendezvous.proto");
    protobuf_codegen::Codegen::new()
        .pure()
        .cargo_out_dir("server_protos")
        .input("protos/rendezvous.proto")
        .include("protos")
        .customize(protobuf_codegen::Customize::default().tokio_bytes(true))
        .run_from_script();
}
