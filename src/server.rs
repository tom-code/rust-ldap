use crate::{ldap, tokiou};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{future::Future, io::Result, pin::Pin, sync::Arc};
use tokio::net::TcpListener;

pub trait Service {
    type Future: Future<Output = Result<Vec<u8>>> + Send + Sync + 'static;
    fn call(&self, req: ldap::Message) -> Self::Future;
}

pub type BoxFuture2<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

pub struct LdapServer {
    listen_address: String,
}

impl LdapServer {
    async fn connection_handler<
        R: tokio::io::AsyncReadExt + Unpin,
        W: tokio::io::AsyncWriteExt + Unpin + Send + 'static,
    >(
        self: &std::sync::Arc<Self>,
        socket: &mut R,
        mut writer: W,
        s: Arc<impl Service + std::marker::Send + std::marker::Sync + 'static>,
    ) -> Result<()> {
        let mut dec = tokiou::DecodeContext::new();
        let mut pending_responses = FuturesUnordered::new();

        let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        tokio::spawn(async move {
            while let Some(i) = writer_rx.recv().await {
                if tokio::io::AsyncWriteExt::write_all(&mut writer, i.as_ref())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                parsed_result = dec.get_message(socket) => {
                    let parsed = parsed_result?;
                    let f = s.call(parsed);
                    pending_responses.push(f);
                }
                Some(resp_result) = pending_responses.next(), if !pending_responses.is_empty() => {
                    match resp_result {
                        Ok(resp) => {
                            if !resp.is_empty()
                                && writer_tx.send(resp).await.is_err() {
                                    log::info!("writer channel closed, stopping writer task");
                                    return Ok(());
                                }
                        }
                        Err(e) => {
                            log::error!("service error: {:?}", e);
                        }
                    }
                }
            }
        }
    }

    pub async fn start_server<S: Service + std::marker::Send + std::marker::Sync + 'static>(
        self: &std::sync::Arc<Self>,
        svc: Arc<S>,
    ) -> Result<()>
    where
        <S as Service>::Future: std::marker::Sync,
        <S as Service>::Future: std::marker::Send,
    {
        log::info!("ldap will listen on {:?}", self.listen_address);
        let listener = TcpListener::bind(&self.listen_address).await?;
        loop {
            let (socket, remote_addr) = listener.accept().await?;
            let s = self.clone();
            let svc1 = svc.clone();
            tokio::spawn(async move {
                log::info!("incoming connection from: {:?}", remote_addr);
                let (mut r, w) = socket.into_split();
                let res = s.connection_handler(&mut r, w, svc1).await;
                log::info!("connection from {:?} terminated {:?}", remote_addr, res);
            });
        }
    }

    pub fn new(listen_address: String) -> Self {
        Self { listen_address }
    }
}
