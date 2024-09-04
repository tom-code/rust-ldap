use crate::codec;
use crate::ldap::{self, Message, MessageParams, MsgBind, MsgBindResponse};
use crate::tokiou;
use std::sync::atomic::AtomicU32;
use std::{collections::HashMap, io::Result};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::oneshot};

struct Context {
    messages: Vec<Message>,
    notif: tokio::sync::oneshot::Sender<Vec<crate::ldap::Message>>,
}

struct Contexts {
    contexts: std::sync::Mutex<HashMap<u32, Context>>,
}

impl Contexts {
    fn new() -> Self {
        Self {
            contexts: std::sync::Mutex::new(HashMap::new()),
        }
    }
    fn add(&self, id: u32, c: Context) {
        let mut l = self.contexts.lock().unwrap();
        l.insert(id, c);
    }
    fn remove(&self, id: u32) {
        let mut l = self.contexts.lock().unwrap();
        l.remove(&id);
    }
    /*fn get(&self, id:u32) -> Option<Context>{
        let mut l = self.contexts.lock().unwrap();
        l.remove(&id)
    }*/
    fn update(
        &self,
        m: Message,
    ) -> Option<(
        Vec<Message>,
        tokio::sync::oneshot::Sender<Vec<ldap::Message>>,
    )> {
        let id = m.id;
        let last_fragment = !matches!(m.params, MessageParams::SearchResult(_));
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
            }
            None => None,
        }
    }
}

pub struct ClientConnection {
    req_writer: tokio::sync::mpsc::Sender<Vec<u8>>,
    contexts: std::sync::Arc<Contexts>,
    last_id: AtomicU32,
}
impl ClientConnection {
    async fn send_request(&self, msg: ldap::Message) -> Result<()> {
        let tosend = match msg.params {
            ldap::MessageParams::Bind(b) => {
                codec::ldap_write_bind_request(msg.id, &b.name, &b.password)
            }
            ldap::MessageParams::BindResponse(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown msg",
                ))
            }
            ldap::MessageParams::Search(s) => codec::ldap_write_search_request(msg.id, &s),
            ldap::MessageParams::SearchResult(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown msg",
                ))
            }
            ldap::MessageParams::MsgSearchResultDone(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown msg",
                ))
            }
            ldap::MessageParams::Unbind(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown msg",
                ))
            }
        }?;
        let res = self.req_writer.send(tosend).await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, e)),
        }
    }

    pub async fn send_request_w(&self, msg: ldap::Message) -> Result<Vec<Message>> {
        let (tx, rx) = oneshot::channel();
        let id = msg.id;
        self.contexts.add(
            id,
            Context {
                notif: tx,
                messages: Vec::new(),
            },
        );
        let res = self.send_request(msg).await;
        if let Err(e) = res {
            self.contexts.remove(id);
            return Err(e);
        };

        let rec = rx.await;
        let recdata = match rec {
            Ok(m) => m,
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, e)),
        };
        Ok(recdata)
    }

    pub async fn send_request_bind(&self, name: &str, password: &str) -> Result<MsgBindResponse> {
        let msg = Message {
            id: self
                .last_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            params: MessageParams::Bind(MsgBind {
                version: 3,
                name: name.to_owned(),
                password: password.to_owned(),
            }),
        };

        let mut res = self.send_request_w(msg).await?;
        if res.len() == 1 {
            if let MessageParams::BindResponse(r) = res.remove(0).params {
                return Ok(r);
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty result",
        ))
    }
}

pub async fn connect(remote_address: &str) -> Result<ClientConnection> {
    let (transmit_tx, mut transmit_rx) = tokio::sync::mpsc::channel(1024);
    let stream = TcpStream::connect(remote_address).await?;
    let (mut reader, mut writer) = stream.into_split();

    let _writer_task = tokio::spawn(async move {
        loop {
            let data: Option<Vec<u8>> = transmit_rx.recv().await;
            match data {
                Some(d) => {
                    if (writer.write_all(d.as_ref()).await).is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    });
    let contexts = std::sync::Arc::new(Contexts::new());
    let contexts_clone = contexts.clone();
    let _reader_task = tokio::spawn(async move {
        let mut decode_context = tokiou::DecodeContext::new();
        loop {
            let res = decode_context.get_message(&mut reader).await;
            let msg = match res {
                Ok(msg) => msg,
                Err(_) => break,
            };
            let out = contexts_clone.update(msg);
            match out {
                Some((m, s)) => {
                    if s.send(m).is_err() {
                        break;
                    }
                }
                None => continue,
            }
        }
    });
    Ok(ClientConnection {
        req_writer: transmit_tx,
        contexts,
        last_id: AtomicU32::new(0),
    })
}
