fn main() {
    #[repr(C, align(8))]
    struct AlignedElf<const N: usize>([u8; N]);

    const ALIGNED: &AlignedElf<{ include_bytes!(
        "../../xdp-ebpf/target/bpfel-unknown-none/release/xdp-ebpf"
    ).len() }> = &AlignedElf(*include_bytes!(
        "../../xdp-ebpf/target/bpfel-unknown-none/release/xdp-ebpf"
    ));

    let elf_bytes: &[u8] = &ALIGNED.0;
    println!("ELF size: {} bytes", elf_bytes.len());
    println!("Magic: {:02x} {:02x} {:02x} {:02x}", elf_bytes[0], elf_bytes[1], elf_bytes[2], elf_bytes[3]);
    println!("Alignment: {}", elf_bytes.as_ptr() as usize % 8);
    
    match aya::EbpfLoader::new().load(elf_bytes) {
        Ok(bpf) => {
            println!("Load OK!");
            for (name, _) in bpf.programs() {
                println!("  program: {}", name);
            }
        }
        Err(e) => {
            println!("Load error: {:?}", e);
        }
    }
}
