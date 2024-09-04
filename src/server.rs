

use crate::{ldap, tokiou};
use tokio::net::TcpListener;
use std::{future::Future, io::Result, pin::Pin, sync::Arc};




pub trait Service {
    type Future: Future<Output = Result<Vec<u8>>> + Send + Sync + 'static;
    fn call(&self, req: ldap::Message) -> Self::Future;
}



pub type BoxFuture2<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

pub struct LdapServer {
    listen_address: String
}



impl LdapServer {
    async fn ldap_reader<R: tokio::io::AsyncReadExt+Unpin, W: tokio::io::AsyncWriteExt+Unpin+Send + 'static> (
        self: &std::sync::Arc<Self>,
        socket : &mut R, mut writer: W, s: Arc<impl Service + std::marker::Send + std::marker::Sync + 'static>
        ) -> Result<()> {

        let mut dec = tokiou::DecodeContext::new();

        let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        tokio::spawn(async move {
            while let Some(i) = writer_rx.recv().await {
                tokio::io::AsyncWriteExt::write_all(&mut writer, i.as_ref()).await.unwrap();
            }
        });
        loop {
            let parsed = dec.get_message(socket).await?;
            let f = s.call(parsed);
            let wtx = writer_tx.clone();
            tokio::spawn(async move {
                let resp = f.await;
                if let Ok(resp) = resp {
                    if !resp.is_empty() {
                        wtx.send(resp).await.unwrap();
                    }
                }
            });

        }
    }

    pub async fn start_server<S: Service + std::marker::Send + std::marker::Sync + 'static>(
        self: &std::sync::Arc<Self>,
        svc: Arc<S>
    ) -> Result<()>
    where
        <S as Service>::Future: std::marker::Sync,
        <S as Service>::Future: std::marker::Send {
        println!("ldap will listen on {:?}", self.listen_address);
        let listener = TcpListener::bind(&self.listen_address).await?;
        loop {
            let (socket, remote_addr) = listener.accept().await?;
            let s = self.clone();
            let svc1 = svc.clone();
            tokio::spawn(async move {
                println!("incoming connection from: {:?}", remote_addr);
                let (mut r, w) = socket.into_split();
                let res = s.ldap_reader(&mut r, w, svc1).await;
                println!("reader done {:?}", res);
            });
        }
    }

    pub fn new(listen_address: String) -> Self {
        Self {
            listen_address,
        }
    }
}


