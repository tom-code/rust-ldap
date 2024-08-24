use std::io::Cursor;
use std::io::Read;
use std::io::Result;

use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;



pub fn read_tag(cursor: &mut Cursor<&[u8]>) -> Result<u8> {
    cursor.read_u8()
}

pub fn read_size(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
    let b1 = cursor.read_u8()? as usize;
    if b1 & 0x80 == 0 {
        return Ok(b1)
    }
    let size = b1 & 0x7f;
    let mut out = 0;
    for _ in 0..size {
        let c = cursor.read_u8()? as usize;
        out = (out << 8) + c;
    }
    Ok(out)
}

pub fn read_uint(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    read_tag(cursor)?;
    let size = read_size(cursor)?;
    let mut out = 0;
    for _ in 0..size {
        let c = cursor.read_u8()? as u32;
        out <<= 8;
        out |= c;
    }
    Ok(out)
}

pub fn read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    read_tag(cursor)?;
    let size = read_size(cursor)?;
    let mut buf = vec![0;size];
    cursor.read_exact(&mut buf)?;
    Ok(std::str::from_utf8(&buf).unwrap().to_owned())
}

pub fn write_tag(buf: &mut Vec<u8>, tag: u8) -> Result<()> {
    buf.write_u8(tag)
}

pub fn asn1_write_len(buf: &mut Vec<u8>, len: u8) -> Result<()> {
    buf.write_u8(len)
}

pub fn write_enum(buf: &mut Vec<u8>, val: u8) -> Result<()> {
    write_tag(buf, 0xa)?;
    asn1_write_len(buf, 1)?;
    buf.write_u8(val)
}
fn write_octet_string(buf: &mut Vec<u8>, val: &[u8]) -> Result<()> {
    write_tag(buf, 0x4)?;
    asn1_write_len(buf, val.len() as u8)?;
    buf.extend_from_slice(val);
    Ok(())
}

pub fn write_int(buf: &mut Vec<u8>, val: u32) -> Result<()> {
    write_tag(buf, 0x2)?;
    if val < 0x80 {
        asn1_write_len(buf, 1)?;
        buf.write_u8(val as u8)
    } else if val < 0x8000 {
        asn1_write_len(buf, 2)?;
        buf.write_u8((val >>8) as u8)?;
        buf.write_u8(val as u8)
    } else if val < 0x800000 {
        asn1_write_len(buf, 3)?;
        buf.write_u8((val >> 16) as u8)?;
        buf.write_u8((val >> 8) as u8)?;
        buf.write_u8(val as u8)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}


#[derive(Debug)]
struct Asn1EncoderStackEntry {
    pos: usize
}

#[derive(Debug)]
pub struct Encoder {
    buffer: Vec<u8>,
    stack: Vec<Asn1EncoderStackEntry>
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            stack: Vec::new(),
        }
    }
    pub fn start_seq(&mut self, tag: u8) -> Result<()> {
        write_tag(&mut self.buffer, tag)?;
        self.stack.push(Asn1EncoderStackEntry{ pos: self.buffer.len() - 1 });
        asn1_write_len(&mut self.buffer, 0)
    }
    pub fn fix(&mut self) {
        while !self.stack.is_empty() {
            self.end_seq()
        }
    }
    pub fn end_seq(&mut self) {
        let i = self.stack.pop();
        if let Some(a) = i {
            let s = self.buffer.len() - a.pos - 2;
            self.buffer[a.pos+1] = s as u8;
        }

    }
    pub fn write_octet_string(&mut self, val: &[u8]) -> Result<()> {
        write_octet_string(&mut self.buffer, val)
    }
    pub fn write_enum(&mut self, val: u8) -> Result<()>{
        write_enum(&mut self.buffer, val)
    }
    pub fn write_int(&mut self, val: u32) -> Result<()> {
        write_int(&mut self.buffer, val)
    }

    /*pub fn dump(&self) {
        //println!("{:02X?}", self.buffer);
        for c in &self.buffer {
            print!("{:02X?}", c);
        }
        println!();
    }*/
    pub fn encode(mut self) -> Vec<u8> {
        self.fix();
        self.buffer
    }
}


#[test]
fn a_test() {
    assert_eq!(read_size(&mut std::io::Cursor::new(&[0x82, 0x27, 0x32])).unwrap(), 10034);
    assert_eq!(read_size(&mut std::io::Cursor::new(&[0x08])).unwrap(), 8);
    let mut buf = Vec::new();
    write_int(&mut buf, 127).unwrap();
    assert_eq!(buf, vec![0x02, 0x01, 0x7f]);

    let mut buf = Vec::new();
    write_int(&mut buf, 128).unwrap();
    assert_eq!(buf, vec![0x02, 0x02, 0x0, 0x80]);

    let mut buf = Vec::new();
    write_int(&mut buf, 256).unwrap();
    assert_eq!(buf, vec![0x02, 0x02, 0x1, 0x0]);
}

