use tokio::{io::AsyncWriteExt, net::TcpStream};
use std::io::Result;


async fn client() -> Result<()> {
    let mut stream = TcpStream::connect("127.0.0.1:389").await?;
    let rq = lds::codec::ldap_write_bind_request(0)?;
    stream.write_all(rq.as_ref()).await.unwrap();


    let mut tb = lds::tokenbucket::TokenBucket::new(20.0);
    let mut id = 10;
    loop {
        tb.get().await;
        id += 1;
        let rq = lds::codec::ldap_write_search_request(id)?;
        stream.write_all(rq.as_ref()).await.unwrap();
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