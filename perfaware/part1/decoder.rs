struct Mov {
    src: Loc,
    dst: Loc,
}

impl Mov {
    fn asm(&self) -> String {
        format!("mov {}, {}",
                self.dst.asm().to_lowercase(),
                self.src.asm().to_lowercase())
    }
}

struct Add {
    src: Loc,
    dst: Loc,
}

impl Add {
    fn asm(&self) -> String {
        format!("add {}, {}",
                self.dst.asm().to_lowercase(),
                self.src.asm().to_lowercase())
    }
}

enum Loc {
    Reg(Reg),
    EAC(EAC),
    Imm8(u8), // this is only applicable when Loc is a src
    Imm16(u16), // this is only applicable when Loc is a src
}

impl Loc {
    fn asm(&self) -> String {
        match self {
            Self::Reg(reg) => reg.asm().to_string(),
            Self::Imm8(n) => format!("byte {}", n),
            Self::Imm16(n) => format!("word {}", n),
            Self::EAC(eac) => eac.asm(),
        }
    }
}


// Effective Address Calculation
struct EAC {
    base: EABase,
    displacement: Option<i16>, // can be either 0, 8, or 16 bits
}

impl EAC {
    fn new(base: EABase, displacement: Option<i16>) -> Self {
        Self { base, displacement }
    }

    fn asm(&self) -> String {
        match self.displacement {
            None => format!("[{}]", self.base.asm()),
            Some(d@0..) => format!("[{} + {}]", self.base.asm(), d),
            Some(d) => format!("[{} - {}]", self.base.asm(), -d),
        }
    }
}

enum EABase {
    BxSi,
    BxDi,
    BpSi,
    BpDi,
    Si,
    Di,
    DirectAddr(u16),
    Bx,
    Bp,
}

impl EABase {
    fn asm(&self) -> String {
        match self {
            Self::BxSi => "bx + si".into(),
            Self::BxDi => "bx + di".into(),
            Self::BpSi => "bp + si".into(),
            Self::BpDi => "bp + di".into(),
            Self::Si => "si".into(),
            Self::Di => "di".into(),
            Self::Bx => "bx".into(),
            Self::Bp => "bp".into(),
            Self::DirectAddr(n) => n.to_string(),
        }
    }
}

struct Reg {
    #[allow(unused)]
    region: Region,
    #[allow(unused)]
    name: &'static str,
    mnemonic: &'static str,
}

impl Reg {
    const fn new(mnemonic: &'static str, name: &'static str, region: Region) -> Self {
        Self { mnemonic, name, region }
    }

    fn asm(&self) -> &str {
        self.mnemonic
    }

    fn acc(w: bool) -> Self {
        if w { Self::AX } else { Self::AL }
    }

    const AL : Reg = Reg::new("AL", "A", Region::Low);
    const AX : Reg = Reg::new("AX", "A", Region::Xtended);
}

// this also works for the R/M field, if MOD = 0b11
// (register to register copy)
fn parse_reg_field(reg: u8, w: bool) -> Reg {
    use Region::*;
    match (reg, w) {
        (0b000, _) => Reg::acc(w),

        (0b001, false) => Reg::new("CL", "C", Low),
        (0b001, true) => Reg::new("CX", "C", Xtended),

        (0b010, false) => Reg::new("DL", "D", Low),
        (0b010, true) => Reg::new("DX", "D", Xtended),

        (0b011, false) => Reg::new("BL", "B", Low),
        (0b011, true) => Reg::new("BX", "B", Xtended),

        (0b100, false) => Reg::new("AH", "A", High),
        (0b100, true) => Reg::new("SP", "SP", Xtended),

        (0b101, false) => Reg::new("CH", "C", High),
        (0b101, true) => Reg::new("BP", "BP", Xtended),

        (0b110, false) => Reg::new("DH", "D", High),
        (0b110, true) => Reg::new("SI", "SI", Xtended),

        (0b111, false) => Reg::new("BH", "B", High),
        (0b111, true) => Reg::new("DI", "DI", Xtended),

        _ => panic!("unexpected reg pattern"),
    }
}

fn parse_r_m_field(r_m_bits: u8, displacement: Option<i16>) -> EAC {
    use EABase::*;
    match r_m_bits {
        0b000 => EAC::new(BxSi, displacement),
        0b001 => EAC::new(BxDi, displacement),
        0b010 => EAC::new(BpSi, displacement),
        0b011 => EAC::new(BpDi, displacement),
        0b100 => EAC::new(Si, displacement),
        0b101 => EAC::new(Di, displacement),
        0b110 if displacement.is_none() => unreachable!("not handling Direct Address from this function, should have used parse_rm_direct_addr"),
        0b110 if displacement.is_some() => EAC::new(Bp, displacement),
        0b111 => EAC::new(Bx, displacement),
        _ => panic!("unexpected bit pattern: 0b_{:b}", r_m_bits),
    }
}

fn parse_rm_direct_addr(direct_addr: u16) -> EAC {
    use EABase::*;
    EAC::new(DirectAddr(direct_addr), None)
}

fn parse_mem_to_acc(bs: &mut impl Iterator<Item = u8>) -> Mov {
    let b0 = bs.next().unwrap();
    let addr = consume_u16(bs);
    // byte 0  
    // 1010000W
    let w = b0 & 0b_0000_0001 != 0; // is_wide
    let dst = Loc::Reg(Reg::acc(w));
    let src = Loc::EAC(EAC::new(EABase::DirectAddr(addr), None));
    Mov { src, dst }
}

fn parse_acc_to_mem(bs: &mut impl Iterator<Item = u8>) -> Mov {
    let b0 = bs.next().unwrap();
    let addr = consume_u16(bs);
    // byte 0  
    // 1010001W
    let w = b0 & 0b_0000_0001 != 0; // is_wide
    let src = Loc::Reg(Reg::acc(w));
    let dst = Loc::EAC(EAC::new(EABase::DirectAddr(addr), None));
    Mov { src, dst }
}

fn parse_r_m_to_r_m(bs: &mut impl Iterator<Item = u8>) -> (Loc, Loc) {
    let b0 = bs.next().unwrap();
    let b1 = bs.next().unwrap();
    
    // XXXXXX: opcode
    // byte 0   byte 1
    // XXXXXXDW MOD|REG|R/M
    //           2   3   3
    let w = b0 & 0b_0000_0001 != 0; // is_wide
    let mod_bits = (b1 & 0b_1100_0000) >> 6;
    let reg_bits = (b1 & 0b_0011_1000) >> 3;
    let r_m_bits = b1 & 0b_0000_0111;

    let d_bit = b0 & 0b00000010 != 0;
    let reg_register = parse_reg_field(reg_bits, w);
    // TODO: we're duplicating this too, so idk if we'll need this again again
    let r_m_loc = match mod_bits {
        0b11 => Loc::Reg(parse_reg_field(r_m_bits, w)),
        0b00 if r_m_bits == 0b110 => {
            Loc::EAC(parse_rm_direct_addr(consume_u16(bs)))
        },
        0b00 => Loc::EAC(parse_r_m_field(r_m_bits, None)),
        0b01 => {
            let displacement = (bs.next().unwrap() as i8) as i16;
            Loc::EAC(parse_r_m_field(r_m_bits, Some(displacement)))
        },
        0b10 => {
            let displacement = consume_i16(bs);
            Loc::EAC(parse_r_m_field(r_m_bits, Some(displacement)))
        },
        _ => panic!("unexpected MOD field: 0b_{:b}", mod_bits),
    };

    if d_bit {
        (r_m_loc, Loc::Reg(reg_register))
    } else {
        (Loc::Reg(reg_register), r_m_loc)
    }
}

fn parse_imm_to_reg(bs: &mut impl Iterator<Item = u8>) -> Mov {
    let b0 = bs.next().unwrap();
    // byte 0    
    // 1011|W|REG
    //      1  3    
    let w = (b0 & 0b_0000_1000) != 0;
    let reg = b0 & 0b_0000_0111;
    let dst = parse_reg_field(reg, w);
    let src = if w {
        Loc::Imm16(consume_u16(bs))
    } else {
        Loc::Imm8(bs.next().unwrap())
    };
    Mov { src, dst: Loc::Reg(dst) }
}

fn parse_imm_to_acc(bs: &mut impl Iterator<Item = u8>) -> (Loc, Loc) {
    let b0 = bs.next().unwrap();
    // byte 0
    // XXXXXXXW
    let w = b0 & 0b_0000_0001 != 0; // is_wide
    if w {
        (Loc::Imm16(consume_u16(bs)), Loc::Reg(Reg::acc(w)))
    } else {
        (Loc::Imm8(bs.next().unwrap()), Loc::Reg(Reg::acc(w)))
    }
}

fn parse_imm_to_r_m(bs: &mut impl Iterator<Item = u8>, should_look_at_s: bool) -> (Loc, Loc) {
    // let mut b_split = bs.peekable();
    //let b_prime = b_split.peek().unwrap(); // This approach wont work. Using peek for the first time on a peekable iter will call next
                                            // on the underlying iterator. This means that we will eventually read an argument byte as an operand byte which is BAD.
    //println!("call b_prime to {:b}", b_prime);
    let b0 = bs.next().unwrap();
    let b1 = bs.next().unwrap();

    // XXXXXX: opcode
    // byte 0   byte 1
    // XXXXXXSW MOD|000|R/M
    //           2       3


    // TODO: duplicated with parse_mov_100_010_xx, i think if we
    // keep going with adding new instructions, i think this
    // pattern is a common one
    let w = b0 & 0b_0000_0001 != 0; // is_wide
    // SPECIAL CASE:
    // for the MOV instruction, `s` can be considered as 
    // always 0
    let s = if should_look_at_s { // is_sign_extended
        b0 & 0b_0000_0010 != 0
    } else {
        false
    };
    let mod_bits = (b1 & 0b_1100_0000) >> 6;
    let r_m_bits = b1 & 0b_0000_0111;
    let r_m_loc = match mod_bits {
        0b11 => Loc::Reg(parse_reg_field(r_m_bits, w)),
        0b00 => Loc::EAC(parse_r_m_field(r_m_bits, None)),
        0b01 => {
            let displacement = (bs.next().unwrap() as i8) as i16;
            Loc::EAC(parse_r_m_field(r_m_bits, Some(displacement)))
        },
        0b10 => {
            let displacement = consume_i16(bs);
            Loc::EAC(parse_r_m_field(r_m_bits, Some(displacement)))
        },
        _ => panic!("unexpected MOD field: 0b_{:b}", mod_bits),
    };
    let src = if w && !s {
        Loc::Imm16(consume_u16(bs))
    } else if w && s {
        // sign extending, not sure if i'm doing it right
        // TODO: make sure we have a test for the sign extension
        let imm16 = (bs.next().unwrap() as i8) as i16;
        let imm16 : u16 = unsafe { std::mem::transmute(imm16) };
        Loc::Imm16(imm16)
    } else {
        Loc::Imm8(bs.next().unwrap())
    };
    (src, r_m_loc)
}

fn consume_u16(bs: &mut impl Iterator<Item = u8>) -> u16 {
    u16::from_le_bytes([bs.next().unwrap(), bs.next().unwrap()])
}

fn consume_i16(bs: &mut impl Iterator<Item = u8>) -> i16 {
    i16::from_le_bytes([bs.next().unwrap(), bs.next().unwrap()])
}

enum Region {
    Xtended, // 16 bits
    Low, // 8 bits
    High, // 8 bits
}

// using https://edge.edx.org/c4x/BITSPilani/EEE231/asset/8086_family_Users_Manual_1_.pdf
// as reference for how to decode the instructions
fn main() {
    let mut args = std::env::args();
    args.next().unwrap();
    let filename = args.next().unwrap_or_else(
        || panic!("Must supply filename"));
    let mut bytes = std::fs::read(filename).unwrap().into_iter().peekable();

    println!("bits 16");
    while let Some(byte) = bytes.peek() {
        // MOV instructions
        if byte >> 2 == 0b_10_0010 {
            let (src, dst) = parse_r_m_to_r_m(&mut bytes);
            println!("{}", Mov { src, dst }.asm());
        } else if byte >> 4 == 0b_1011  {
            let asm = parse_imm_to_reg(&mut bytes).asm();
            println!("{}", asm);
        } else if byte >> 1 == 0b_110_0011  {
            println!("GOT MOV INSTR FOR IMM TO RM: {:b}", bytes.peek().unwrap());
            let (src, dst) = parse_imm_to_r_m(&mut bytes, false);
            println!("{}", Mov { src, dst }.asm());
        } else if byte >> 1 == 0b_101_0000  {
            let asm = parse_mem_to_acc(&mut bytes).asm();
            println!("{}", asm);
        } else if byte >> 1 == 0b_101_0001  {
            let asm = parse_acc_to_mem(&mut bytes).asm();
            println!("{}", asm);
        // ADD instructions
        // reg/memory with register to either
        } else if byte >> 2 == 0b_00_0000 {
            let (src, dst) = parse_r_m_to_r_m(&mut bytes);
            println!("{}", Add { src, dst }.asm());
        // immediate to register / memory
        } else if byte >> 2 == 0b_10_0000 {
            println!("GOT ADD INSTR FOR IMM TO RM: {:b}", bytes.peek().unwrap());
            let (src, dst) = parse_imm_to_r_m(&mut bytes, true);
            println!("{}", Add { src, dst }.asm());
        // immediate to accumulator
        } else if byte >> 1 == 0b_000_0010 {
            let (src, dst) = parse_imm_to_acc(&mut bytes);
            println!("{}", Add { src, dst }.asm());
        } else {
            panic!("0b{:b}", byte);
        }
    }
}
