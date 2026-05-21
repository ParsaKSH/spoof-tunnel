fn main() {
    // Tell cargo to re-run this build script (and recompile)
    // whenever the eBPF binary changes.
    println!("cargo:rerun-if-changed=../xdp-ebpf/target/bpfel-unknown-none/release/xdp-ebpf");
}
