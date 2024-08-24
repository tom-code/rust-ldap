
use futures::StreamExt;
use tokio::net::TcpListener;
use std::{future::Future, io::Result, pin::Pin};

mod asn1;
mod codec;






#[derive(Debug, Clone)]
pub struct FilterAttributeValueAssertion {
    pub name: String,
    pub value: String
}

#[derive(Debug, Clone)]
pub struct FilterPresent {
    pub name: String
}

#[derive(Debug, Clone)]
pub struct FilterAnd {
    pub items: Vec<Filter>
}

#[derive(Debug, Clone)]
pub enum Filter {
    Empty(),
    AttributeValueAssertion(FilterAttributeValueAssertion),
    Present(FilterPresent),
    And(FilterAnd)
}


#[derive(Debug, Clone)]
pub struct MsgBind{
    pub version: u32,
    pub name: String,
    pub password: String
}

#[derive(Debug, Clone)]
pub struct MsgSearch {
    pub base_object: String,
    pub scope: u32,
    pub deref: u32,
    pub filter: Filter,
    pub size_limit: u32,
    pub time_limit: u32
}

#[derive(Debug, Clone)]
pub struct MsgUnbind {
}

#[derive(Debug, Clone)]
pub enum MsgE {
    Bind(MsgBind),
    Search(MsgSearch),
    Unbind(MsgUnbind)
}

#[derive(Debug, Clone)]
pub struct Message {
    id: u32,
    params: MsgE
}

pub trait Service {
    type Future: Future<Output = Result<u32>>;
    fn call(&mut self, req: Message) -> Self::Future;
}

struct Test1 {

}

impl Service for Test1 {
    type Future = Pin<Box<dyn Future<Output = Result<u32>>>>;

    fn call(&mut self, req: Message) -> Self::Future {
        let r = async {
            println!("ret from service");
            Ok(1)
        };
        Box::pin(r)
    }
}


struct LdapServer {

}



impl LdapServer {
    async fn ldap_reader<R: tokio::io::AsyncReadExt+Unpin, W: tokio::io::AsyncWriteExt+Unpin>(self: &std::sync::Arc<Self>, socket : &mut R, writer: &mut W) -> Result<()> {
        let mut buffer: [u8; 1000] = [0; 1000];
        let mut have = 0;
        loop {
            let res = tokio::io::AsyncReadExt::read(socket, &mut buffer[have..]).await?;
            if res == 0 {
                break Ok(())
            }
            have += res;
            while have > 0 {
                let (parsed, parsed_size) = match codec::parse_message(&buffer[..have]) {
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
                //println!("{:?}", parsed);
                match parsed.params {
                    MsgE::Bind(_)=> {
                        let resp = codec::ldap_write_bind_response(parsed.id)?;
                        tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;
                    },
                    MsgE::Search(_)=>{
                        let resp = codec::ldap_write_search_res_entry(parsed.id)?;
                        tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;

                        let resp = codec::ldap_write_search_res_done(parsed.id)?;
                        tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;
                    },
                    _ => {}
                };

                if parsed_size != have {
                    buffer.copy_within(parsed_size..have, 0);
                }
                have -= parsed_size;
            }
        }
    }

    async fn start_server(self: &std::sync::Arc<Self>) -> Result<()> {
        println!("ldap will listen on 0.0.0.0:389");
        let listener = TcpListener::bind("0.0.0.0:389").await?;
        loop {
            let (socket, remote_addr) = listener.accept().await?;
            let s = self.clone();
            tokio::spawn(async move {
                println!("incoming connection from: {:?}", remote_addr);
                let (mut r, mut w) = socket.into_split();
                let res = s.ldap_reader(&mut r, &mut w).await;
                println!("reader done {:?}", res);
            });
        }
    }

    async fn start2(self: &std::sync::Arc<Self>, mut s: impl Service) {
        let mut tasks = futures::stream::FuturesUnordered::new();
        let t2 = s.call(Message { id: 1, params: MsgE::Unbind(MsgUnbind{ })});
        let t1 = s.call(Message { id: 1, params: MsgE::Unbind(MsgUnbind{ })});
        tasks.push(t1);
        tasks.push(t2);
        while let Some(result) = tasks.next().await {
            println!(">>{:?}", result);
        }
    }
}



fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let ldap = std::sync::Arc::new(LdapServer{});
        //ldap.start2(Test1{}).await;
        let res = ldap.start_server().await;
        if let Err(e) = res {
            println!("{:?}", e)
        }
    });
}

/*
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
*/