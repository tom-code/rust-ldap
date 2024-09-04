use lds::ldap::{DerefAliases, Message, MessageParams, MsgSearch, SearchScope};
use std::io::Result;

async fn client_example() -> Result<()> {
    let connection = lds::client::connect("127.0.0.1:389").await?;
    let res = connection.send_request_bind("used", "password").await?;
    println!("response: {:?}", res);
    if res.res == 0 {
        let res2 = connection
            .send_request_w(Message {
                id: 1,
                params: MessageParams::Search(MsgSearch {
                    base_object: "b1".to_owned(),
                    scope: SearchScope::SingleLevel,
                    deref: DerefAliases::DerefAlways,
                    filter: lds::ldap::Filter::Present(lds::ldap::FilterPresent {
                        name: "pp".to_owned(),
                    }),
                    size_limit: 0,
                    time_limit: 0,
                }),
            })
            .await;
        println!("response2: {:?}", res2);
    }

    Ok(())
}

fn main() {
    println!("client");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        //client().await.unwrap();
        client_example().await.unwrap();
    });
}
