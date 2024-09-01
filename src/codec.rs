use std::io::Cursor;
use std::io::Read;
use std::io::Result;

use crate::asn1;
use crate::asn1::read_string;
use crate::asn1::Encoder;
use crate::ldap::Filter;
use crate::ldap::FilterAnd;
use crate::ldap::FilterAttributeValueAssertion;
use crate::ldap::FilterPresent;
use crate::ldap::Message;
use crate::ldap::MsgBind;
use crate::ldap::MsgBindResponse;
use crate::ldap::MsgE;
use crate::ldap::MsgSearch;
use crate::ldap::MsgSearchResult;
use crate::ldap::MsgSearchResultDone;
use crate::ldap::MsgUnbind;




const LDAP_MAX_PARAM_SIZE: usize = 1024;

pub fn ldap_read_filter_attr_val_assertion(cursor: &mut Cursor<&[u8]>) -> Result<FilterAttributeValueAssertion> {
    let size = asn1::read_size(cursor)?;
    if size > LDAP_MAX_PARAM_SIZE {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
    let name = asn1::read_string(cursor)?;
    let value = asn1::read_string(cursor)?;
    Ok(FilterAttributeValueAssertion {
        name,
        value,
    })
}
pub fn ldap_read_filter_attr_desc(cursor: &mut Cursor<&[u8]>) -> Result<FilterPresent> {
    let size = asn1::read_size(cursor)?;
    if size > LDAP_MAX_PARAM_SIZE {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
    let mut buf = vec![0;size];
    cursor.read_exact(&mut buf)?;
    let name = std::str::from_utf8(&buf).unwrap().to_owned();
    Ok(FilterPresent { name })
}

pub fn ldap_read_filter_and(cursor: &mut Cursor<&[u8]>) -> Result<FilterAnd> {
    let size = asn1::read_size(cursor)?;
    if size > LDAP_MAX_PARAM_SIZE {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
    }
    let pos = cursor.position();
    let mut items: Vec<Filter> = Vec::new();
    while cursor.position() < (pos + size as u64) {
        let f = ldap_read_filter(cursor)?;
        items.push(f)
    }
    Ok(FilterAnd { items })
}

pub fn ldap_read_filter(cursor: &mut Cursor<&[u8]>) -> Result<Filter> {
    let tag = asn1::read_tag(cursor)?;
    match tag {
        0xa0 => { // and
            Ok(Filter::And(ldap_read_filter_and(cursor)?))
        }
        0xa3 => { // equality match
            Ok(Filter::EqualityMatch(ldap_read_filter_attr_val_assertion(cursor)?))
        }
        0x87 => { // present
            Ok(Filter::Present(ldap_read_filter_attr_desc(cursor)?))
        }
        _ => {Ok(Filter::Empty())}
    }
}

pub fn ldap_write_bind_request(id: u32, name: &str, password: &str) -> Result<Vec<u8>> {
    let mut e = asn1::Encoder::new();
    e.start_seq(0x30)?;
    e.write_int(id)?;
    e.start_seq(0x60)?;
    e.write_int(3)?; //version
    e.write_octet_string(name.as_bytes())?;
    e.write_octet_string_with_tag(0x80, password.as_bytes())?;
    Ok(e.encode())
}

fn enc_filter(e: &mut Encoder, f: &Filter) -> Result<()> {
    match f {
        Filter::Empty() => Ok(()),
        Filter::EqualityMatch(f) => {
            e.start_seq(0xa3)?;
            e.write_octet_string(f.name.as_bytes())?;
            e.write_octet_string(f.value.as_bytes())?;
            e.end_seq();
            Ok(())
        },
        Filter::Present(f) => {
            e.write_octet_string_with_tag(0x87, f.name.as_bytes())
        },
        Filter::And(f) => {
            e.start_seq(0xa0)?;
            for a in &f.items {
                enc_filter(e, a)?
            }
            e.end_seq();
            Ok(())
        },
    }
}

pub fn ldap_write_search_request(id: u32, msg: &MsgSearch) -> Result<Vec<u8>> {
    let mut e = asn1::Encoder::new();
    e.start_seq(0x30)?;
    e.write_int(id)?;
    e.start_seq(0x63)?;
    e.write_octet_string(msg.base_object.as_bytes())?;
    e.write_enum(msg.scope as u8)?;
    e.write_enum(msg.deref as u8)?;
    e.write_int(msg.size_limit)?;
    e.write_int(msg.time_limit)?;
    e.write_bool(false)?;

    enc_filter(&mut e, &msg.filter)?;
    Ok(e.encode())
}

pub fn ldap_write_bind_response(id: u32) -> Result<Vec<u8>> {
    let mut e = asn1::Encoder::new();
    e.start_seq(0x30)?;
    e.write_int(id)?;
    e.start_seq(0x61)?;
    e.write_enum(0)?;
    e.write_octet_string(&[])?;
    e.write_octet_string(&[])?;
    Ok(e.encode())
}

pub fn ldap_write_search_res_done(id: u32, res: u32) -> Result<Vec<u8>> {
    let mut e = asn1::Encoder::new();
    e.start_seq(0x30)?;
    e.write_int(id)?;
    e.start_seq(0x65)?;
    e.write_enum(res as  u8)?;
    e.write_octet_string("a1".as_bytes())?;
    e.write_octet_string("a2".as_bytes())?;
    e.end_seq();
    e.end_seq();
    Ok(e.encode())
}

pub fn ldap_write_search_res_entry(id: u32, name: &str, attrs: &Vec<crate::ldap::PartialAttribute>) -> Result<Vec<u8>> {
    let mut e = asn1::Encoder::new();
    e.start_seq(0x30)?;
    e.write_int(id)?;
    e.start_seq(0x64)?;
    e.write_octet_string(name.as_bytes())?;
    e.start_seq(0x30)?;

    for attr in attrs {
        e.start_seq(0x30)?;
        e.write_octet_string(attr.name.as_bytes())?;
        e.start_seq(0x31)?;
        for value in &attr.values {
            e.write_octet_string(value.as_bytes())?;
        }
        e.end_seq();
        e.end_seq();
    }

    Ok(e.encode())
}


pub fn parse_message(data: &[u8]) -> Result<(Message, usize)>{
    //println!("parsing {:?}", hex::encode(data));
    if data.len() < 4 {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
    let mut cursor = std::io::Cursor::new(data);
    let _start_seq_tag = asn1::read_tag(&mut cursor)?;
    let start_seq_len = asn1::read_size(&mut cursor)? as usize;
    if data.len() < (start_seq_len + 2) {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
    let message_id = asn1::read_uint(&mut cursor)?;
    let msg_tag = asn1::read_tag(&mut cursor)?;
    match msg_tag {
        0x60 => { // bind
            let _app_size = asn1::read_size(&mut cursor);
            let version = asn1::read_uint(&mut cursor)?;
            let name = asn1::read_string(&mut cursor)?;
            let password = asn1::read_string(&mut cursor).unwrap_or("".to_owned());
            Ok((Message {
                id: message_id,
                params: MsgE::Bind(MsgBind{
                    version,
                    name,
                    password
                }),
            }, start_seq_len + 2))
        },
        0x61 => { // bind response
            let _app_size = asn1::read_size(&mut cursor);
            let res = asn1::read_uint(&mut cursor)?;
            let matched_dn = asn1::read_string(&mut cursor)?;
            let diag = asn1::read_string(&mut cursor)?;
            Ok((Message {
                id: message_id,
                params: MsgE::BindResponse(MsgBindResponse{ res, matched_dn, diag }),
            }, start_seq_len + 2))
        }
        0x63 => { // search
            let _app_size = asn1::read_size(&mut cursor);
            let base_object = asn1::read_string(&mut cursor)?;
            let scope = asn1::read_uint(&mut cursor)?;
            let deref = asn1::read_uint(&mut cursor)?;
            let size_limit = asn1::read_uint(&mut cursor)?;
            let time_limit = asn1::read_uint(&mut cursor)?;
            let _typed_only = asn1::read_uint(&mut cursor);
            let filter = ldap_read_filter(&mut cursor)?;
            Ok((Message {
                id: message_id,
                params: MsgE::Search(MsgSearch{
                    base_object,
                    scope,
                    deref,
                    filter,
                    size_limit,
                    time_limit
                }),
            }, start_seq_len + 2))
        },
        0x64 => { // search result
            let _app_size = asn1::read_size(&mut cursor);
            let name = asn1::read_string(&mut cursor)?;
            let _tag = asn1::read_tag(&mut cursor)?;
            let _size = asn1::read_size(&mut cursor)?;
            let mut partial_attr_list = Vec::new();
            while cursor.position() < (start_seq_len + 2) as u64 {
                let _tag = asn1::read_tag(&mut cursor)?;
                let _size = asn1::read_size(&mut cursor)?;
                let attr_name: String = asn1::read_string(&mut cursor)?;
                let _tag = asn1::read_tag(&mut cursor)?;
                let size = asn1::read_size(&mut cursor)?;
                let mut buf =  vec![0; size];
                cursor.read_exact(buf.as_mut_slice())?;
                let mut cur2 = std::io::Cursor::new(buf.as_slice());
                let mut attr_values = Vec::new();
                while cur2.position() < size as u64 {
                    let s = asn1::read_string(&mut cur2)?;
                    attr_values.push(s);
                }
                let attribute = crate::ldap::PartialAttribute { name: attr_name, values: attr_values };
                partial_attr_list.push(attribute);
            }
            Ok ((Message {
                id: message_id,
                params: MsgE::SearchResult(MsgSearchResult {name, values: partial_attr_list })}, start_seq_len + 2 ))
        },
        0x65 => { // search result done
            let _app_size = asn1::read_size(&mut cursor);
            let res = asn1::read_uint(&mut cursor)?;
            Ok ((Message {
                id: message_id,
                params: MsgE::MsgSearchResultDone(MsgSearchResultDone {res})}, start_seq_len + 2 ))
        }

        0x42 => {
            Ok((Message {
                id: message_id,
                params: MsgE::Unbind(MsgUnbind{
                }),
            }, start_seq_len + 2))
        }
        r => {
            println!("unknown req {:x}", r);
            Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
        }
    }
}



#[test]
fn search_test() {
    let d1 = parse_message(hex::decode("3029020102632404000a01020a0100020100020100010100a00f8703617861a30804027373040273733000".as_bytes()).unwrap().as_ref()).unwrap();
    println!("{:?}", d1);
    assert_eq!(d1.1, 43);
    let m = d1.0;
    assert_eq!(m.id, 2);
    if let MsgE::Search(s) = m.params {
        assert_eq!(s.base_object, "");
        assert_eq!(s.scope, 2);
        assert_eq!(s.deref, 0);
        assert_eq!(s.size_limit, 0);
        assert_eq!(s.time_limit, 0);
        if let Filter::And(fa) = s.filter {
            assert_eq!(fa.items.len(), 2);
            if let Filter::EqualityMatch(fa1) = &fa.items[1] {
                assert_eq!(fa1.name, "ss");
                assert_eq!(fa1.value, "ss");
            } else {
                unreachable!();
            }
            if let Filter::Present(fa1) = &fa.items[0] {
                assert_eq!(fa1.name, "axa");
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
    } else {
        unreachable!();
    }
    //let m.params
}

#[test]
fn bind_test() {
    let d1 = parse_message(hex::decode("3013020101600e0201030402787880056865736c6f".as_bytes()).unwrap().as_ref()).unwrap();
    println!("{:?}", d1);
    assert_eq!(d1.1, 21);
    let m = d1.0;
    assert_eq!(m.id, 1);
    if let MsgE::Bind(s) = m.params {
        assert_eq!(s.name, "xx");
        assert_eq!(s.password, "heslo");
        assert_eq!(s.version, 3);
    } else {
        unreachable!();
    }
    //let m.params
}