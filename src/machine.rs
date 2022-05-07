use anyhow::Result;
use std::mem::size_of;
use memoffset::offset_of;

#[repr(u8)]
#[derive(Debug, num_enum::TryFromPrimitive, num_enum::IntoPrimitive)]
pub enum Opcode {
    Const,
    Load,
    Store,
    Add,
    Mul,
    Vmctx,
    Vmexit,
}

#[repr(u8)]
#[derive(num_enum::IntoPrimitive)]
pub enum Register {
    Rax,
    Rcx,
    Rdx,
    Rbx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl From<iced_x86::Register> for Register {
    fn from(reg: iced_x86::Register) -> Self {
        match reg {
            iced_x86::Register::RAX => Register::Rax,
            iced_x86::Register::RCX => Register::Rcx,
            iced_x86::Register::RDX => Register::Rdx,
            iced_x86::Register::RBX => Register::Rbx,
            iced_x86::Register::RSP => Register::Rsp,
            iced_x86::Register::RBP => Register::Rbp,
            iced_x86::Register::RSI => Register::Rsi,
            iced_x86::Register::RDI => Register::Rdi,
            iced_x86::Register::R8 => Register::R8,
            iced_x86::Register::R9 => Register::R9,
            iced_x86::Register::R10 => Register::R10,
            iced_x86::Register::R11 => Register::R11,
            iced_x86::Register::R12 => Register::R12,
            iced_x86::Register::R13 => Register::R13,
            iced_x86::Register::R14 => Register::R14,
            iced_x86::Register::R15 => Register::R15,
            iced_x86::Register::EAX => Register::Rax,
            iced_x86::Register::ECX => Register::Rcx,
            iced_x86::Register::EDX => Register::Rdx,
            iced_x86::Register::EBX => Register::Rbx,
            iced_x86::Register::ESP => Register::Rsp,
            iced_x86::Register::EBP => Register::Rbp,
            iced_x86::Register::ESI => Register::Rsi,
            iced_x86::Register::EDI => Register::Rdi,
            iced_x86::Register::R8D => Register::R8,
            iced_x86::Register::R9D => Register::R9,
            iced_x86::Register::R10D => Register::R10,
            iced_x86::Register::R11D => Register::R11,
            iced_x86::Register::R12D => Register::R12,
            iced_x86::Register::R13D => Register::R13,
            iced_x86::Register::R14D => Register::R14,
            iced_x86::Register::R15D => Register::R15,
            _ => panic!("unsupported register"),
        }
    }
}
pub struct Machine {
    pc: *const u8,
    sp: *mut u64,
    pub regs: [u64; 16],
    program: Vec<u8>,
    vmstack: Vec<u64>,
    cpustack: Vec<u8>,
    pub vmenter: region::Allocation,
    vmexit: region::Allocation,
}

impl Machine {
    #[cfg(target_env = "msvc")]
    #[allow(clippy::fn_to_numeric_cast)]
    pub fn new(program: &[u8]) -> Result<Self> {
        use iced_x86::code_asm::*;

        let mut m = Self {
            pc: std::ptr::null(),
            sp: std::ptr::null_mut(),
            regs: [0; 16],
            program: program.to_vec(),
            vmstack: [0; 0x1000].to_vec(),
            cpustack: [0; 0x1000].to_vec(),
            vmenter: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
            vmexit: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
        };

        // Generate VMENTER.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rcx, Register::Rcx.into()),
            (&rdx, Register::Rdx.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            (&rsi, Register::Rsi.into()),
            (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        let mut a = CodeAssembler::new(64)?;

        a.mov(rax, &m as *const _ as u64)?;

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(qword_ptr(rax + offset), **reg)?;
        }

        // Switch to the VM's CPU stack.
        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - size_of::<u64>()) as u64
        };
        a.mov(rsp, vm_rsp)?;

        a.mov(rcx, rax)?;
        a.mov(rax, Self::run as u64)?;
        a.jmp(rax)?;

        let insts = a.assemble(m.vmenter.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmenter.as_mut_ptr(), insts.len());
        };

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            (&rsi, Register::Rsi.into()),
            (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        let mut a = CodeAssembler::new(64)?;

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, qword_ptr(rcx + offset))?;
        }

        a.jmp(rdx)?;

        let insts = a.assemble(m.vmexit.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmexit.as_mut_ptr(), insts.len());
        };

        Ok(m)
    }

    #[cfg(target_env = "gnu")]
    #[allow(clippy::fn_to_numeric_cast)]
    pub fn new(program: &[u8]) -> Result<Self> {
        use iced_x86::code_asm::*;

        let mut m = Self {
            pc: std::ptr::null(),
            sp: std::ptr::null_mut(),
            regs: [0; 16],
            program: program.to_vec(),
            vmstack: [0; 0x1000].to_vec(),
            cpustack: [0; 0x1000].to_vec(),
            vmenter: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
            vmexit: region::alloc(region::page::size(), region::Protection::READ_WRITE_EXECUTE)?,
        };

        // Generate VMENTER.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rcx, Register::Rcx.into()),
            (&rdx, Register::Rdx.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            (&rsi, Register::Rsi.into()),
            (&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        let mut a = CodeAssembler::new(64)?;

        a.mov(rax, &m as *const _ as u64)?;

        // Store the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(qword_ptr(rax + offset), **reg)?;
        }

        // Switch to the VM's CPU stack.
        let vm_rsp = unsafe {
            m.cpustack
                .as_ptr()
                .add(m.cpustack.len() - 0x100 - size_of::<u64>()) as u64
        };
        a.mov(rsp, vm_rsp)?;

        a.mov(rdi, rax)?;
        a.mov(rax, Self::run as u64)?;
        a.jmp(rax)?;

        let insts = a.assemble(m.vmenter.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmenter.as_mut_ptr(), insts.len());
        };

        // Generate VMEXIT.
        let regmap: &[(&AsmRegister64, u8)] = &[
            (&rax, Register::Rax.into()),
            (&rcx, Register::Rcx.into()),
            (&rdx, Register::Rdx.into()),
            (&rbx, Register::Rbx.into()),
            (&rsp, Register::Rsp.into()),
            (&rbp, Register::Rbp.into()),
            //(&rsi, Register::Rsi.into()),
            //(&rdi, Register::Rdi.into()),
            (&r8, Register::R8.into()),
            (&r9, Register::R9.into()),
            (&r10, Register::R10.into()),
            (&r11, Register::R11.into()),
            (&r12, Register::R12.into()),
            (&r13, Register::R13.into()),
            (&r14, Register::R14.into()),
            (&r15, Register::R15.into()),
        ];

        let mut a = CodeAssembler::new(64)?;

        // Restore the GPRs
        for (reg, regid) in regmap.iter() {
            let offset = offset_of!(Machine, regs) + *regid as usize * 8;
            a.mov(**reg, qword_ptr(rdi + offset))?;
        }

        a.jmp(rsi)?;

        let insts = a.assemble(m.vmexit.as_ptr::<u64>() as u64)?;

        unsafe {
            std::ptr::copy(insts.as_ptr(), m.vmexit.as_mut_ptr(), insts.len());
        };

        Ok(m)
    }

    #[allow(clippy::missing_safety_doc)]
    pub unsafe extern "C" fn run(&mut self) {
        self.pc = self.program.as_ptr();
        self.sp = self.vmstack.as_mut_ptr();

        while self.pc < self.program.as_ptr_range().end {
            let op = Opcode::try_from(*self.pc).unwrap();
            self.pc = self.pc.add(1);

            match op {
                Opcode::Const => {
                    *self.sp.add(1) = *(self.pc as *const u64);
                    self.sp = self.sp.add(1);
                    self.pc = self.pc.add(size_of::<u64>());
                }
                Opcode::Load => *self.sp = *(*self.sp as *const u64),
                Opcode::Store => {
                    *(*self.sp as *mut u64) = *self.sp.sub(1);
                    self.sp = self.sp.sub(2);
                }
                Opcode::Add => {
                    *self.sp.sub(1) = (*self.sp.sub(1)).wrapping_add(*self.sp);
                    self.sp = self.sp.sub(1);
                }
                Opcode::Mul => {
                    *self.sp.sub(1) = (*self.sp.sub(1)).wrapping_mul(*self.sp);
                    self.sp = self.sp.sub(1);
                }
                Opcode::Vmctx => {
                    *self.sp.add(1) = self as *const _ as u64;
                    self.sp = self.sp.add(1);
                }
                Opcode::Vmexit => {
                    let exit_ip = *self.sp;
                    self.sp = self.sp.sub(1);
                    let vmexit: extern "C" fn(&mut Machine, u64) =
                        std::mem::transmute(self.vmexit.as_ptr::<()>());
                    vmexit(self, exit_ip);
                }
            }
        }
    }
}

#[derive(Default)]
pub struct Assembler {
    program: Vec<u8>,
}

impl Assembler {
    pub fn assemble(&self) -> Vec<u8> {
        self.program.clone()
    }

    pub fn const_(&mut self, v: u64) {
        self.emit(Opcode::Const);
        self.emit_u64(v);
    }

    pub fn load(&mut self) {
        self.emit(Opcode::Load);
    }

    pub fn store(&mut self) {
        self.emit(Opcode::Store);
    }

    pub fn add(&mut self) {
        self.emit(Opcode::Add);
    }

    pub fn mul(&mut self) {
        self.emit(Opcode::Mul);
    }

    pub fn vmctx(&mut self) {
        self.emit(Opcode::Vmctx);
    }

    pub fn vmexit(&mut self) {
        self.emit(Opcode::Vmexit);
    }

    fn emit(&mut self, op: Opcode) {
        self.program.push(op as u8);
    }

    fn emit_u64(&mut self, value: u64) {
        self.program.extend_from_slice(&value.to_le_bytes());
    }
}

pub fn disassemble(program: &[u8]) -> Result<String> {
    let mut s = String::new();
    let mut pc = program.as_ptr();

    while pc < program.as_ptr_range().end {
        let op = Opcode::try_from(unsafe { *pc })?;
        pc = unsafe { pc.add(1) };

        s.push_str(format!("{:?}", op).as_str());

        #[allow(clippy::single_match)]
        match op {
            Opcode::Const => unsafe {
                let v = *(pc as *const u64);
                pc = pc.add(size_of::<u64>());
                s.push_str(format!(" {}", v).as_str());
            },
            _ => {}
        }

        s.push('\n');
    }

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembler_and_machine() {
        let mut a = Assembler::default();
        let x = 2u64;
        let y = 3u64;
        let z = 0u64;

        a.const_(&x as *const _ as u64);
        a.load();
        a.const_(&y as *const _ as u64);
        a.load();
        a.mul();
        a.const_(&z as *const _ as u64);
        a.store();

        unsafe { Machine::new(&a.assemble()).unwrap().run() };
        assert_eq!(z, 6);
    }
}