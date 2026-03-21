use std::time::{Duration, Instant};

pub struct TokenBucket {
    tokens: u64,
    max_tokens: u64,
    speed: f64,
    remain: f64,
    last_time: Instant,
    sleep_duration: Duration,
}

impl TokenBucket {
    pub fn new(speed: f64) -> Self {
        let sleep_secs = (1.0 / speed).clamp(0.001, 0.1);
        Self {
            tokens: 0,
            max_tokens: (speed as u64).max(1),
            speed,
            remain: 0.0,
            last_time: Instant::now(),
            sleep_duration: Duration::from_secs_f64(sleep_secs),
        }
    }
    /*pub fn set_speed(&mut self, s: f64) {
        self.speed = s;
    }*/
    pub async fn get(&mut self) {
        loop {
            if self.tokens > 0 {
                self.tokens -= 1;
                return;
            }
            let now = Instant::now();
            let time_diff = now.duration_since(self.last_time);
            let give = (time_diff.as_micros() as f64) * self.speed / 1_000_000.0 + self.remain;
            //self.remain = 0.0;
            if give >= 1.0 {
                let whole = give as u64;
                self.remain = give - (whole as f64);
                self.tokens = (self.tokens + whole).min(self.max_tokens);
                self.last_time = now;
                continue;
            }
            if self.tokens < 1 {
                tokio::time::sleep(self.sleep_duration).await;
            }
        }
    }
}
