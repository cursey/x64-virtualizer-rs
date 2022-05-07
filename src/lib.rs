pub mod machine;
pub mod virtualizer;

#[cfg(test)]
mod tests {
    use crate::virtualizer::virtualize;
    use crate::machine::disassemble;

    #[test]
    fn virtualize_and_disassemble() {
        const SHELLCODE: &[u8] = &[
            0x55, 0x48, 0x89, 0xE5, 0x89, 0x7D, 0xFC, 0x8B, 0x45, 0xFC, 0x0F, 0xAF, 0xC0, 0x5D, 0xC3,
        ];
        let program = &virtualize(SHELLCODE);
        println!("{}", disassemble(program).unwrap());
    }
}