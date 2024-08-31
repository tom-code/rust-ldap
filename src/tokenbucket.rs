use std::time::Instant;

pub struct TokenBucket {
    tokens: u64,
    speed: f64,
    remain: f64,
    last_time: Instant,
}

impl TokenBucket {
    pub fn new(speed: f64) -> Self {
        Self {
            tokens: 0,
            speed,
            remain: 0.0,
            last_time: Instant::now(),
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
            let give = (time_diff.as_micros() as f64) * self.speed / 1000.0 + self.remain;
            //self.remain = 0.0;
            if give >= 1.0 {
                let whole = give as u64;
                self.remain = give - (whole as f64);
                self.tokens += whole;
                self.last_time = now;
                continue;
            }
            if self.tokens < 1 {
                tokio::time::sleep(core::time::Duration::from_millis(20)).await;
            }
        }
    }
}
