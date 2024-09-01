use lds::ldap::{self, Message, MsgBind, MsgE, MsgSearch};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::oneshot};
use std::{collections::HashMap, io::Result, time::Duration};


/*
struct DecodeContext {
    buffer: [u8; 1000],
    have: usize
}

impl DecodeContext {
    async fn get_message<R: tokio::io::AsyncRead + Unpin>(&mut self, s: &mut R) -> Result<Message> {
        loop {
            let (parsed, parsed_size) = match lds::codec::parse_message(&self.buffer[..self.have]) {
                Ok(r) => r,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
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
}*/
struct Client {

}


struct Context {
    messages: Vec<Message>,
    notif: tokio::sync::oneshot::Sender<Vec<lds::ldap::Message>>
}

struct Contexts {
    contexts: std::sync::Mutex<HashMap<u32, Context>>,
}

impl Contexts {
    fn new() -> Self {
        Self {
            contexts: std::sync::Mutex::new(HashMap::new())
        }
    }
    fn add(&self, id:u32, c: Context) {
        let mut l = self.contexts.lock().unwrap();
        l.insert(id, c);
    }
    fn remove(&self, id:u32) {
        let mut l = self.contexts.lock().unwrap();
        l.remove(&id);
    }
    fn get(&self, id:u32) -> Option<Context>{
        let mut l = self.contexts.lock().unwrap();
        l.remove(&id)
    }
    fn update(&self, m: Message) -> Option<(Vec<Message>, tokio::sync::oneshot::Sender<Vec<lds::ldap::Message>>)> {
        let id = m.id;
        let last_fragment = !matches!(m.params, MsgE::SearchResult(_));
        let mut l = self.contexts.lock().unwrap();
        let c = l.get_mut(&id);
        match c {
            Some(c) => {
                c.messages.push(m);
                if last_fragment {
                    let m = l.remove(&id).unwrap();
                    Some((m.messages, m.notif))
                } else {
                    None
                }
            },
            None => None,
        }
    }
}

struct ClientConnection {
    req_writer: tokio::sync::mpsc::Sender<Vec<u8>>,
    writer_task: tokio::task::JoinHandle<()>,
    contexts: std::sync::Arc<Contexts>,
}
impl ClientConnection {
    async fn send_request(&self, msg: ldap::Message) -> Result<()> {
        let tosend = match msg.params {
            ldap::MsgE::Bind(b) => {
                lds::codec::ldap_write_bind_request(msg.id, &b.name, &b.password)
            },
            ldap::MsgE::BindResponse(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown msg")),
            ldap::MsgE::Search(s) => {
                lds::codec::ldap_write_search_request(msg.id, &s)
            },
            ldap::MsgE::SearchResult(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown msg")),
            ldap::MsgE::MsgSearchResultDone(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown msg")),
            ldap::MsgE::Unbind(_) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown msg")),
        }?;
        let res = self.req_writer.send(tosend).await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, e)),
        }
    }

    async fn send_request_w(&self, msg: ldap::Message) -> Result<Vec<Message>> {
        let (tx, rx) = oneshot::channel();
        let id = msg.id;
        self.contexts.add(id, Context { notif: tx, messages: Vec::new() });
        let res = self.send_request(msg).await;
        if let Err(e) = res {
            self.contexts.remove(id);
            return Err(e)
        };
    
        let rec = rx.await;
        let recdata = match rec {
            Ok(m) => m,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, e))
        };


        Ok(recdata)
    }

}
impl Client {
    async fn connect(&self) -> Result<ClientConnection> {
        let (transmit_tx, mut transmit_rx) = tokio::sync::mpsc::channel(1024);
        let stream = TcpStream::connect("127.0.0.1:389").await?;
        let (mut reader, mut writer) = stream.into_split();

        let writer_task = tokio::spawn(async move {
            loop {
                let data: Option<Vec<u8>> = transmit_rx.recv().await;
                match data {
                    Some(d) => {
                        println!("wrote to socket {:?}", d);
                        writer.write_all(d.as_ref()).await.unwrap();
                    },
                    None => break
                }
            }
        });
        let contexts = std::sync::Arc::new(Contexts::new());
        let contextsc = contexts.clone();
        let reader_task = tokio::spawn(async move {
            let mut dc = lds::tokiou::DecodeContext::new();
            loop {
                let msg = dc.get_message(&mut reader).await.unwrap();
                println!("{:?}", msg);
                let out = contextsc.update(msg);
                match out {
                    Some((m, s)) => {
                        s.send(m).unwrap();
                    },
                    None => continue,
                }
            }
        });
        Ok(ClientConnection { req_writer: transmit_tx, writer_task, contexts })
    }
}

async fn client() -> Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:389").await?;
    let (mut reader, mut writer) = stream.split();
    let rq = lds::codec::ldap_write_bind_request(0, "name", "pwd")?;
    writer.write_all(rq.as_ref()).await.unwrap();
    let mut dc = lds::tokiou::DecodeContext::new();
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

async fn client2() -> Result<()> {
    let c = Client{};
    let connection = c.connect().await?;
    let res = connection.send_request_w(
    Message{
           id: 0,
           params: MsgE::Bind(MsgBind{ version: 3, name: "n1".to_owned(), password: "p1".to_owned() }),
        },
    ).await?;
    println!("response: {:?}", res);
    let res2 = connection.send_request_w(Message{
        id: 1,
        params: MsgE::Search(
            MsgSearch {
                base_object: "b1".to_owned(),
                scope: 0,
                deref: 0,
                filter: lds::ldap::Filter::Present(lds::ldap::FilterPresent { name: "pp".to_owned() }),
                size_limit: 0,
                time_limit: 0 }),
    }).await;
    println!("response2: {:?}", res2);
    tokio::time::sleep(Duration::from_secs(1)).await;

    Ok(())
}


fn main() {
    println!("client");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        //client().await.unwrap();
        client2().await.unwrap();
    });
}