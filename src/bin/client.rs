use lds::ldap::Message;
use tokio::{io::AsyncWriteExt, net::{tcp::ReadHalf, TcpStream}};
use std::io::Result;



struct DecContext {
    buffer: [u8; 1000],
    have: usize
}

impl DecContext {
    async fn get_message(&mut self, s: &mut ReadHalf<'_>) -> Result<Message> {
        loop {
            let (parsed, parsed_size) = match lds::codec::parse_message(&self.buffer[..self.have]) {
                Ok(r) => r,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        //break
                        let res = tokio::io::AsyncReadExt::read(s, &mut self.buffer[self.have..]).await?;
                        if res == 0 {
                            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "eof"))
                        }
                        self.have += res;
                        continue
                    } else {
                        return Err(e)
                    }
                }
            };
            if parsed_size != self.have {
                self.buffer.copy_within(parsed_size..self.have, 0);
            }
            self.have -= parsed_size;
            return Ok(parsed)
        }
    }
    fn new() -> Self {
        Self{ buffer: [0; 1000], have: 0 }
    }
}

async fn client() -> Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:389").await?;
    let (mut reader, mut writer) = stream.split();
    let rq = lds::codec::ldap_write_bind_request(0, "name", "pwd")?;
    writer.write_all(rq.as_ref()).await.unwrap();
    let mut dc = DecContext::new();
    let parsed = dc.get_message(&mut reader).await;
    println!("{:?}", parsed);


    let mut tb = lds::tokenbucket::TokenBucket::new(0.01);
    let mut id = 10;
    loop {
        tb.get().await;
        id += 1;
        let rq = lds::codec::ldap_write_search_request(id, &lds::ldap::MsgSearch{
            base_object: "base".to_owned(),
            scope: 0,
            deref: 0,
            filter: lds::ldap::Filter::Present(lds::ldap::FilterPresent { name: "pp".to_owned() }),
            size_limit: 0,
            time_limit: 0
        })?;
        writer.write_all(rq.as_ref()).await.unwrap();

        let parsed = dc.get_message(&mut reader).await;
        println!("{:?}", parsed);
        let parsed = dc.get_message(&mut reader).await;
        println!("{:?}", parsed);
    }

    Ok(())
}


fn main() {
    println!("client");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        client().await.unwrap();
    });
}