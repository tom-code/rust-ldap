
use futures::StreamExt;
use ldap::PartialAttribute;
use tokio::net::TcpListener;
use std::{future::Future, io::Result, pin::Pin, sync::Arc};

mod asn1;
mod codec;
mod ldap;
mod tokiou;




pub trait Service {
    type Future: Future<Output = Result<Vec<u8>>> + Send + Sync + 'static;
    fn call(&self, req: ldap::Message) -> Self::Future;
}


struct Test1 {

}

impl Service for Test1  {
    type Future = Pin<Box<dyn Future<Output = Result<Vec<u8>>> +Send + Sync>>;

    fn call(&self, req: ldap::Message) -> Self::Future {
        let id = req.id;
        let r = async move {
            //println!("ret from service");

            match req.params {
                ldap::MsgE::Bind(_)=> {
                    let resp = codec::ldap_write_bind_response(id, 0)?;
                    Ok(resp)
                },
                ldap::MsgE::Unbind(_)=> {
                    //let resp = codec::ldap_write_bind_response(id, 0)?;   // << wrong!
                    Ok(vec![])
                },
                ldap::MsgE::Search(_)=>{
                    let mut resp1 = codec::ldap_write_search_res_entry(id,
                        "n1",
                        &vec![
                            PartialAttribute {
                                name: "a1".to_owned(),
                                values: vec!["aaa".to_owned(), "bbbb".to_owned()] },
                            PartialAttribute {
                                name: "a2".to_owned(),
                                values: vec!["aaa2".to_owned(), "bbbb2".to_owned()] }
                        ])?;
                    //Ok(resp)

                    let mut resp2 = codec::ldap_write_search_res_done(id, 1)?;
                    resp1.append(&mut resp2);
                    Ok(resp1)
                },
                _ => {Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown request"))}
            }

            //Ok("aaa".as_bytes().to_owned())
        };
        Box::pin(r)
    }
}



//pub type BoxFuture2<'a, T> = Pin<Box<dyn Future<Output = T> + Send + Sync + 'a>>;
pub type BoxFuture2<T> = Pin<Box<dyn Future<Output = T> + Send + Sync>>;

struct LdapServer {
    //tasks :futures::stream::FuturesUnordered<BoxFuture2<Result<Vec<u8>>>>
    //tasks :futures::stream::FuturesUnordered<T>
}



impl LdapServer {
    async fn ldap_reader<R: tokio::io::AsyncReadExt+Unpin, W: tokio::io::AsyncWriteExt+Unpin+Send + 'static>
    (self: &std::sync::Arc<Self>, socket : &mut R, mut writer: W, s: Arc<impl Service + std::marker::Send + std::marker::Sync + 'static>
        ) -> Result<()> {
        let mut buffer: [u8; 1000] = [0; 1000];
        let mut have = 0;
        //let dec = tokiou::DecodeContext::new()

        let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1024);
        tokio::spawn(async move {
            //loop {
                while let Some(i) = writer_rx.recv().await {
                    tokio::io::AsyncWriteExt::write_all(&mut writer, i.as_ref()).await.unwrap();
                }
            //}
        });
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
                        println!("errx {:?}", e);
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            break
                        } else {
                            return Err(e)
                        }
                    }
                };
                println!("{:?}", parsed);
                {
                    //let l = s.lock().await;
                    //let resp = s.call(parsed).await.unwrap();
                    //tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;
                    //let f = s.call(parsed);
                    //tasks.push(Box::pin(f));
                }
                let f = s.call(parsed);
                let wtx = writer_tx.clone();
                tokio::spawn(async move {
                    let resp = f.await.unwrap();
                    if !resp.is_empty() {
                        wtx.send(resp).await.unwrap();
                    }
                    //tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await.unwrap();
                });
                
                //tokio::io::AsyncWriteExt::write_all(writer, resp.as_ref()).await?;
                //println!("{:?}", parsed);
                /*match parsed.params {
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
                };*/

                if parsed_size != have {
                    buffer.copy_within(parsed_size..have, 0);
                }
                have -= parsed_size;
            }
        }
    }

    //async fn start_server(self: &std::sync::Arc<Self>, svc: Arc<impl Service + std::marker::Send + std::marker::Sync + 'static>) -> Result<()> {
        async fn start_server<S: Service + std::marker::Send + std::marker::Sync + 'static>(self: &std::sync::Arc<Self>, svc: Arc<S>) -> Result<()> where
        <S as Service>::Future: std::marker::Sync,
        <S as Service>::Future: std::marker::Send {
        println!("ldap will listen on 0.0.0.0:389");
        let listener = TcpListener::bind("0.0.0.0:389").await?;
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

    async fn start2(self: &std::sync::Arc<Self>, s: impl Service) {
        let mut tasks = futures::stream::FuturesUnordered::new();
        let t2 = s.call(ldap::Message { id: 1, params: ldap::MsgE::Unbind(ldap::MsgUnbind{ })});
        let t1 = s.call(ldap::Message { id: 1, params: ldap::MsgE::Unbind(ldap::MsgUnbind{ })});
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
        let ldap = std::sync::Arc::new(LdapServer{ /*tasks: futures::stream::FuturesUnordered::new()*/ });
        //ldap.start2(Test1{}).await;
        let res = ldap.start_server(Arc::new(Test1{})).await;
        if let Err(e) = res {
            println!("{:?}", e)
        }
    });
}

