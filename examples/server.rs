use lds::{
    codec,
    ldap::{self, PartialAttribute},
    server::LdapServer,
};
use std::{future::Future, io::Result, pin::Pin, sync::Arc};

struct Test1 {}

impl lds::server::Service for Test1 {
    type Future = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + Sync>>;

    fn call(&self, req: ldap::Message) -> Self::Future {
        println!("{:?}", req);
        let id = req.id;
        let r = async move {
            //println!("ret from service");

            match req.params {
                ldap::MessageParams::Bind(_) => {
                    let resp = codec::ldap_write_bind_response(id, 0)?;
                    Ok(resp)
                }
                ldap::MessageParams::Unbind(_) => Ok(vec![]),
                ldap::MessageParams::Search(_) => {
                    let mut resp1 = codec::ldap_write_search_res_entry(
                        id,
                        "n1",
                        &vec![
                            PartialAttribute {
                                name: "a1".to_owned(),
                                values: vec!["aaa".to_owned(), "bbbb".to_owned()],
                            },
                            PartialAttribute {
                                name: "a2".to_owned(),
                                values: vec!["aaa2".to_owned(), "bbbb2".to_owned()],
                            },
                        ],
                    )?;

                    let mut resp2 = codec::ldap_write_search_res_done(id, 1)?;
                    resp1.append(&mut resp2);
                    Ok(resp1)
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unknown request",
                )),
            }
        };
        Box::pin(r)
    }
}

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let ldap = std::sync::Arc::new(LdapServer::new("0.0.0.0:389".to_owned()));
        let res = ldap.start_server(Arc::new(Test1 {})).await;
        if let Err(e) = res {
            println!("{:?}", e)
        }
    });
}
