use lds::{
    ldap::{DerefAliases, MessageParams, MsgSearch, SearchScope},
    tokenbucket::TokenBucket,
};
use std::{
    io::Result,
    sync::Arc,
    time::{Duration, Instant},
};

async fn client_example() -> Result<()> {
    let connection = Arc::new(lds::client::connect("127.0.0.1:389").await?);
    let res = connection.send_request_bind("used", "password").await?;
    log::info!("response: {:?}", res);
    if res.res == 0 {
        let mut tasks = Vec::new();
        for _ in 0..1000 {
            let connection = connection.clone();
            let t = tokio::spawn(async move {
                let res2 = connection
                    .send_request_wpar(MessageParams::Search(MsgSearch {
                        base_object: "b1".to_owned(),
                        scope: SearchScope::SingleLevel,
                        deref: DerefAliases::DerefAlways,
                        filter: lds::ldap::Filter::Present(lds::ldap::FilterPresent {
                            name: "pp".to_owned(),
                        }),
                        size_limit: 0,
                        time_limit: 0,
                    }))
                    .await;
                log::info!("response2: {:?}", res2);
            });
            tasks.push(t);
        }
        for t in tasks {
            t.await?;
        }
    }

    Ok(())
}

async fn client_example2(remote_addres: &str, speed: f64, duration: Duration) -> Result<()> {
    let connection = Arc::new(lds::client::connect(remote_addres).await?);
    let res = connection.send_request_bind("used", "password").await?;
    log::info!("response: {:?}", res);
    if res.res == 0 {
        let mut tb = TokenBucket::new(speed);
        let mut n = 0;
        let start_time = Instant::now();
        loop {
            tb.get().await;
            if start_time.elapsed() > duration {
                break;
            }
            let connection = connection.clone();
            n += 1;
            tokio::spawn(async move {
                let res2 = connection
                    .send_request_wpar(MessageParams::Search(MsgSearch {
                        base_object: "b1".to_owned(),
                        scope: SearchScope::SingleLevel,
                        deref: DerefAliases::DerefAlways,
                        //filter: lds::ldap::Filter::Present(lds::ldap::FilterPresent {
                        //    name: "pp".to_owned(),
                        //}),
                        filter: lds::ldap::Filter::EqualityMatch(
                            lds::ldap::FilterAttributeValueAssertion {
                                name: "name".to_owned(),
                                value: format!("val-{}", n),
                            },
                        ),
                        size_limit: 0,
                        time_limit: 0,
                    }))
                    .await;
                log::info!("response2: {:?}", res2);
            });
        }
    }

    Ok(())
}

#[derive(clap::Parser)]
#[command()]
struct ConfigArgs {
    #[arg(short, long, default_value = "127.0.0.1:389")]
    remote: String,
    #[arg(short, long, default_value_t = 0.1)]
    speed: f64,
    #[arg(short, long, default_value_t = 10)]
    duration: u64,
}

fn main() {
    let env = env_logger::Env::default();
    env_logger::init_from_env(env);
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        //.filter_level(log::LevelFilter::Trace)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis));
    //.parse_env(env);
    let args = <ConfigArgs as clap::Parser>::parse();

    log::info!("client");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        //client().await.unwrap();
        client_example2(&args.remote, args.speed, Duration::from_secs(args.duration))
            .await
            .unwrap();
    });
}
