//use tokio::io::AsyncWriteExt;
//use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use std::io::Cursor;
use std::io::Read;
use std::io::Result;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};




fn asn1_read_tag(cursor: &mut Cursor<&[u8]>) -> Result<u8> {
    cursor.read_u8()
}

fn asn1_read_size(cursor: &mut Cursor<&[u8]>) -> Result<usize> {
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

fn asn1_read_uint(cursor: &mut Cursor<&[u8]>) -> Result<u32> {
    asn1_read_tag(cursor)?;
    let size = asn1_read_size(cursor)?;
    let mut out = 0;
    for _ in 0..size {
        let c = cursor.read_u8()? as u32;
        out <<= 8;
        out |= c;
    }
    Ok(out)
}

fn asn1_read_string(cursor: &mut Cursor<&[u8]>) -> Result<String> {
    asn1_read_tag(cursor)?;
    let size = asn1_read_size(cursor)?;
    let mut buf = vec![0;size];
    cursor.read_exact(&mut buf)?;
    Ok(std::str::from_utf8(&buf).unwrap().to_owned())
}

fn ldap_read_filter_ava(cursor: &mut Cursor<&[u8]>) -> Result<FilterAttributeValueAssertion> {
    let _size = asn1_read_size(cursor)?;
    let name = asn1_read_string(cursor)?;
    let value = asn1_read_string(cursor)?;
    Ok(FilterAttributeValueAssertion {
        name,
        value,
    })
}
fn ldap_read_filter_ad(cursor: &mut Cursor<&[u8]>) -> Result<FilterPresent> {
    let size = asn1_read_size(cursor)?;
    let mut buf = vec![0;size];
    cursor.read_exact(&mut buf)?;
    let name = std::str::from_utf8(&buf).unwrap().to_owned();
    Ok(FilterPresent { name })
}

fn ldap_read_filter_and(cursor: &mut Cursor<&[u8]>) -> Result<FilterAnd> {
    let size = asn1_read_size(cursor)? as u64;
    let pos = cursor.position();
    let mut items: Vec<Filter> = Vec::new();
    while cursor.position() < (pos + size) {
        let f = ldap_read_filter(cursor)?;
        items.push(f)
    }
    Ok(FilterAnd { items })
}

fn ldap_read_filter(cursor: &mut Cursor<&[u8]>) -> Result<Filter> {
    let tag = asn1_read_tag(cursor)?;
    println!("filter tag {:x}", tag);
    match tag {
        0xa0 => { // and
            Ok(Filter::And(ldap_read_filter_and(cursor)?))
        }
        0xa3 => { // equality match
            Ok(Filter::AttributeValueAssertion(ldap_read_filter_ava(cursor)?))
        }
        0x87 => { // present
            Ok(Filter::Present(ldap_read_filter_ad(cursor)?))
        }
        _ => {Ok(Filter::Empty())}
    }
}


fn asn1_write_tag(buf: &mut Vec<u8>, tag: u8) {
    buf.write_u8(tag).unwrap()
}

fn asn1_write_len(buf: &mut Vec<u8>, len: u8) {
    buf.write_u8(len).unwrap()
}

fn asn1_write_enum(buf: &mut Vec<u8>, val: u8) {
    asn1_write_tag(buf, 0xa);
    asn1_write_len(buf, 1);
    buf.write_u8(val).unwrap();
}

fn asn1_write_int(buf: &mut Vec<u8>, val: u8) {
    asn1_write_tag(buf, 0x2);
    asn1_write_len(buf, 1);
    buf.write_u8(val).unwrap();
}

fn asn1_write_octet_string(buf: &mut Vec<u8>, val: &[u8]) {
    asn1_write_tag(buf, 0x4);
    asn1_write_len(buf, val.len() as u8);
    buf.extend_from_slice(val);
}

fn ldap_write_bind_response(id: u32) -> Vec<u8> {
    let mut e = Asn1Encoder { buffer: Vec::new(), stack: Vec::new() };
    e.start_seq(0x30);
    e.write_int(id as u8);
    e.start_seq(0x61);
    e.write_enum(0);
    e.write_octet_string(&[]);
    e.write_octet_string(&[]);
    e.encode()
}

fn ldap_write_search_res_done(id: u32) -> Vec<u8> {
    let mut e = Asn1Encoder { buffer: Vec::new(), stack: Vec::new() };
    e.start_seq(0x30);
    e.write_int(id as u8);
    e.start_seq(0x65);
    e.write_enum(32);
    e.write_octet_string("a1".as_bytes());
    e.write_octet_string("a2".as_bytes());
    e.end_seq();
    e.end_seq();
    e.encode()
}

fn ldap_write_search_res_entry(id: u32) -> Vec<u8> {
    let mut e = Asn1Encoder { buffer: Vec::new(), stack: Vec::new() };
    e.start_seq(0x30);
    e.write_int(id as u8);
    e.start_seq(0x64);
    e.write_octet_string("abc".as_bytes());
    e.start_seq(0x30);

    e.start_seq(0x30);
    e.write_octet_string("a1".as_bytes());
    e.start_seq(0x31);
    e.write_octet_string("a2".as_bytes());
    e.write_octet_string("a3".as_bytes());
    e.end_seq();
    e.end_seq();

    e.start_seq(0x30);
    e.write_octet_string("b1".as_bytes());
    e.start_seq(0x31);
    e.write_octet_string("b2".as_bytes());
    e.write_octet_string("b3".as_bytes());
    e.end_seq();
    e.end_seq();

    e.encode()
}


#[derive(Debug)]
struct Asn1EncoderStackEntry {
    pos: usize
}

#[derive(Debug)]
struct Asn1Encoder {
    buffer: Vec<u8>,
    stack: Vec<Asn1EncoderStackEntry>
}

impl Asn1Encoder {
    pub fn start_seq(&mut self, tag: u8) {
        asn1_write_tag(&mut self.buffer, tag);
        self.stack.push(Asn1EncoderStackEntry{ pos: self.buffer.len() - 1 });
        asn1_write_len(&mut self.buffer, 0);
    }
    fn fix(&mut self) {
        while !self.stack.is_empty() {
            self.end_seq()
        }
    }
    pub fn end_seq(&mut self) {
        let i = self.stack.pop();
        if let Some(a) = i {
            println!("{:?} {:?}", self.buffer.len(), a.pos);
            let s = self.buffer.len() - a.pos - 2;
            println!("{:?}", a.pos);
            self.buffer[a.pos+1] = s as u8;
        }

    }
    pub fn write_octet_string(&mut self, val: &[u8]) {
        asn1_write_octet_string(&mut self.buffer, val)
    }
    pub fn write_enum(&mut self, val: u8) {
        asn1_write_enum(&mut self.buffer, val);
    }
    pub fn write_int(&mut self, val: u8) {
        asn1_write_int(&mut self.buffer, val);
    }

    pub fn dump(&self) {
        //println!("{:02X?}", self.buffer);
        for c in &self.buffer {
            print!("{:02X?}", c);
        }
        println!();
    }
    pub fn encode(mut self) -> Vec<u8> {
        self.fix();
        self.buffer
    }
}
#[derive(Debug, Clone)]
struct FilterAttributeValueAssertion {
    name: String,
    value: String
}

#[derive(Debug, Clone)]
struct FilterPresent {
    name: String
}

#[derive(Debug, Clone)]
struct FilterAnd {
    items: Vec<Filter>
}

#[derive(Debug, Clone)]
enum Filter {
    Empty(),
    AttributeValueAssertion(FilterAttributeValueAssertion),
    Present(FilterPresent),
    And(FilterAnd)
}


#[derive(Debug, Clone)]
struct MsgBind{
    version: u32,
    name: String,
    password: String
}

#[derive(Debug, Clone)]
struct MsgSearch {
    base_object: String,
    scope: u32,
    deref: u32,
    filter: Filter
}

#[derive(Debug, Clone)]
struct MsgUnbind {
}

#[derive(Debug, Clone)]
enum MsgE {
    Bind(MsgBind),
    Search(MsgSearch),
    Unbind(MsgUnbind)
}

#[derive(Debug, Clone)]
struct Message {
    id: u32,
    params: MsgE
}


fn parse_message(data: &[u8]) -> Result<(Message, usize)>{
    let mut cursor = std::io::Cursor::new(data);
    let start_seq_tag = asn1_read_tag(&mut cursor)?;
    let start_seq_len = asn1_read_size(&mut cursor)? as usize;
    if data.len() < (start_seq_len + 2) {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
    let message_id = asn1_read_uint(&mut cursor)?;
    let msg_tag = asn1_read_tag(&mut cursor)?;
    match msg_tag {
        0x60 => {
            let _app_size = asn1_read_size(&mut cursor);
            let version = asn1_read_uint(&mut cursor)?;
            let name = asn1_read_string(&mut cursor)?;
            let password = asn1_read_string(&mut cursor)?;
            Ok((Message {
                id: message_id,
                params: MsgE::Bind(MsgBind{
                    version,
                    name,
                    password
                }),
            }, start_seq_len + 2))
        },
        0x63 => {
            let _app_size = asn1_read_size(&mut cursor);
            let base_object = asn1_read_string(&mut cursor)?;
            let scope = asn1_read_uint(&mut cursor)?;
            let deref = asn1_read_uint(&mut cursor)?;
            let size_limit = asn1_read_uint(&mut cursor);
            let time_limit = asn1_read_uint(&mut cursor);
            let _typed_only = asn1_read_uint(&mut cursor);
            let filter = ldap_read_filter(&mut cursor)?;
            Ok((Message {
                id: message_id,
                params: MsgE::Search(MsgSearch{
                    base_object,
                    scope,
                    deref,
                    filter
                }),
            }, start_seq_len + 2))
        },
        0x42 => {
            Ok((Message {
                id: message_id,
                params: MsgE::Unbind(MsgUnbind{
                }),
            }, start_seq_len + 2))
        }
        _ => Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
}


async fn ldap_reader<R: tokio::io::AsyncReadExt+Unpin, W: tokio::io::AsyncWriteExt+Unpin>(socket : &mut R, writer: &mut W) -> Result<()> {
    let mut buffer: [u8; 1000] = [0; 1000];
    let mut have = 0;
    loop {
        let res = tokio::io::AsyncReadExt::read(socket, &mut buffer[have..]).await?;
        if res == 0 {
            break Ok(())
        }
        have += res;
        while have > 0 {
            //println!("{:x?} {:?}", buffer, have);
            let (parsed, parsed_size) = match parse_message(&buffer[..have]) {
                Ok(r) => r,
                Err(e) => {
                    println!("err {:?}", e);
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        break
                    } else {
                        return Err(e)
                    }
                }
            };
            println!("{:?}", parsed);
            //have = 0;
            match parsed.params {
                MsgE::Bind(_)=> {
                    let resp = ldap_write_bind_response(parsed.id);
                    tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;
                },
                MsgE::Search(_)=>{
                    let resp = ldap_write_search_res_entry(parsed.id);
                    tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;

                    let resp = ldap_write_search_res_done(parsed.id);
                    tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;
                },
                _ => {}
            };
            let mut sb = "".to_owned();
            for n in &buffer[..have] {
                sb.push_str(&format!("{:02x}", n));
            }
            //println!("{}", sb);
            if parsed_size != have {
                buffer.copy_within(parsed_size..have, 0);
            }
            have -= parsed_size;
        }
    }
}

async fn server() -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:389").await?;
    loop {
        let (socket, _remote_addr) = listener.accept().await?;
        tokio::spawn(async move {
            println!("incoming");
            let (mut r, mut w) = socket.into_split();
            let res = ldap_reader(&mut r, &mut w).await;
            println!("reader done {:?}", res);
        });
    }
}



fn main() {
    let mut e = Asn1Encoder { buffer: Vec::new(), stack: Vec::new() };
    /*e.add_seq(0x30);
    e.write_int(1);
    e.add_seq(0x64);
    e.write_octet_string("abc".as_bytes());
    e.add_seq(0x30);
    e.add_seq(0x30);
    e.write_octet_string("a1".as_bytes());
    e.write_octet_string("a2".as_bytes());
    e.add_seq(0x30);
    e.write_int(1);
    e.add_seq(0x64);
    e.write_octet_string("abc".as_bytes());*/
    e.start_seq(0x30);
    e.start_seq(0x30);
    e.write_octet_string("a1".as_bytes());
    e.end_seq();
    e.start_seq(0x30);
    e.write_octet_string("a2".as_bytes());
    e.end_seq();
    e.end_seq();

    println!("{:?}", e);
    e.fix();
    println!("{:?}", e);
    e.dump();
    println!("start2");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let res = server().await;
        if let Err(e) = res {
            println!("{:?}", e)
        }
    });
}


#[tokio::test]
async fn reader_test() {
    let unbind: &[u8] = &[0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00];
    let mut reader = tokio_test::io::Builder::new()
        .read(unbind)
        .build();
    let mut writer = tokio_test::io::Builder::new()
        //.write(b"Thanks for your message.\r\n")
        .build();
    let _ = ldap_reader(&mut reader, &mut writer).await;


    let unbind1: &[u8] = &[0x30, 0x05];
    let unbind2: &[u8] = &[0x02, 0x01, 0x03, 0x42, 0x00];
    let mut reader = tokio_test::io::Builder::new()
        .read(unbind1)
        .read(unbind2)
        .build();
    let mut writer = tokio_test::io::Builder::new()
        //.write(b"Thanks for your message.\r\n")
        .build();
    let _ = ldap_reader(&mut reader, &mut writer).await;
}

#[test]
fn prim_test() {
    assert_eq!(asn1_read_size(&mut std::io::Cursor::new(&[0x82, 0x27, 0x32])).unwrap(), 10034);
    assert_eq!(asn1_read_size(&mut std::io::Cursor::new(&[0x08])).unwrap(), 8);
}