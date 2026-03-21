use futures::stream::{FuturesUnordered, StreamExt};
use lds::{
    ldap::{DerefAliases, MessageParams, MsgSearch, SearchScope},
    tokenbucket::TokenBucket,
};
use std::{
    io::Result,
    sync::Arc,
    time::{Duration, Instant},
};

/// Fixed-load blast: spawns exactly 1000 concurrent search requests with no rate limiting
/// or concurrency cap. Uses a `Present` filter. All tasks are fired immediately and then
/// joined. Good for a quick smoke test of the server under sudden load.
async fn client_example(remote_address: &str) -> Result<()> {
    let connection = Arc::new(lds::client::connect(remote_address).await?);
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

/// Rate-limited load test with unbounded concurrency. Sends requests at `speed` req/s via a
/// token bucket for the given `duration`, then sleeps 5 s to let in-flight requests drain.
/// Uses an `EqualityMatch` filter with a unique value per request (`val-{n}`). Reports total
/// sent count. In-flight request count is uncapped — backpressure comes only from the token bucket.
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
        println!("did send {}", n);
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    Ok(())
}

/// Rate-limited load test with bounded concurrency and throughput metrics. Behaves like
/// `client_example2` but caps in-flight requests at `max_concurrent` using `FuturesUnordered`,
/// providing real backpressure. Tracks both sent and completed counts and logs throughput
/// (req/s) every 10 000 completions, with a final summary printed at the end.
async fn client_example3(remote_address: &str, speed: f64, duration: Duration, max_concurrent: usize) -> Result<()> {
    let connection = Arc::new(lds::client::connect(remote_address).await?);
    let res = connection.send_request_bind("used", "password").await?;
    log::info!("response: {:?}", res);

    if res.res == 0 {
        let mut tb = TokenBucket::new(speed);
        let mut n = 0;
        let start_time = Instant::now();
        let mut pending_requests = FuturesUnordered::new();
        let mut completed = 0;

        loop {
            // Try to send new requests if we have capacity and time remaining
            while pending_requests.len() < max_concurrent && start_time.elapsed() <= duration {
                tb.get().await;
                if start_time.elapsed() > duration {
                    break;
                }

                let connection = connection.clone();
                n += 1;
                let request_future = async move {
                    connection
                        .send_request_wpar(MessageParams::Search(MsgSearch {
                            base_object: "b1".to_owned(),
                            scope: SearchScope::SingleLevel,
                            deref: DerefAliases::DerefAlways,
                            filter: lds::ldap::Filter::EqualityMatch(
                                lds::ldap::FilterAttributeValueAssertion {
                                    name: "name".to_owned(),
                                    value: format!("val-{}", n),
                                },
                            ),
                            size_limit: 0,
                            time_limit: 0,
                        }))
                        .await
                };
                pending_requests.push(request_future);
            }

            // Break if no more requests to send and none pending
            if pending_requests.is_empty() {
                break;
            }

            // Wait for at least one request to complete
            if let Some(res2) = pending_requests.next().await {
                completed += 1;

                // Log progress every 10000 responses
                if completed % 10000 == 0 {
                    let elapsed = start_time.elapsed();
                    let rate = completed as f64 / elapsed.as_secs_f64();
                    log::info!("Progress: {} responses completed in {:.2}s (rate: {:.2} req/s)", 
                              completed, elapsed.as_secs_f64(), rate);
                }

                log::debug!("response2: {:?}", res2);
            }
        }

        let elapsed = start_time.elapsed();
        let final_rate = completed as f64 / elapsed.as_secs_f64();
        println!("Final: Sent {} requests, completed {} responses in {:.2}s (rate: {:.2} req/s)", 
                n, completed, elapsed.as_secs_f64(), final_rate);
    }

    Ok(())
}

#[derive(clap::Parser)]
#[command()]
struct ConfigArgs {
    /// LDAP server address
    #[arg(short, long, default_value = "127.0.0.1:389")]
    remote: String,
    /// Target send rate in requests per second (examples 2 and 3)
    #[arg(short, long, default_value_t = 100.0)]
    speed: f64,
    /// How long to run the load test in seconds (examples 2 and 3)
    #[arg(short, long, default_value_t = 10)]
    duration: u64,
    /// Maximum number of in-flight requests at once (example 3 only)
    #[arg(short, long, default_value_t = 100)]
    max_concurrent: usize,
    /// Which example to run:
    ///   1 - fixed 1000-request blast, no rate limit
    ///   2 - rate-limited, unbounded concurrency
    ///   3 - rate-limited, bounded concurrency with metrics (default)
    #[arg(short, long, default_value_t = 3, value_parser = clap::value_parser!(u8).range(1..=3))]
    example: u8,
}

fn main() {
    //let env = env_logger::Env::default();
    //env_logger::init_from_env(env);
    env_logger::Builder::new()
        .target(env_logger::Target::Stdout)
        .filter_level(log::LevelFilter::Info)
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis)).init();
    //.parse_env(env);
    let args = <ConfigArgs as clap::Parser>::parse();

    log::info!("client");

    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        match args.example {
            1 => client_example(&args.remote).await.unwrap(),
            2 => client_example2(&args.remote, args.speed, Duration::from_secs(args.duration))
                .await
                .unwrap(),
            3 => client_example3(&args.remote, args.speed, Duration::from_secs(args.duration), args.max_concurrent)
                .await
                .unwrap(),
            _ => unreachable!(),
        }
    });
}
