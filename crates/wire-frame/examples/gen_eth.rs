use std::io::Write;
use wire_frame::{frame, Namespace};

fn main() {
    let bytecode = b"0x608060405234801561001057600080fd5b50";
    let chain_ref = [1u8; 32]; // chain ID 1 padded
    let framed = frame(Namespace::Eip155, &chain_ref, bytecode);
    std::io::stdout().write_all(&framed).unwrap();
}
