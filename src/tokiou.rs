use std::io::Result;

use crate::ldap::Message;

const MAX_SIZE: usize = 1024 * 32;

pub struct DecodeContext {
    buffer: [u8; MAX_SIZE],
    have: usize,
}

impl DecodeContext {
    pub async fn get_message<R: tokio::io::AsyncRead + Unpin>(
        &mut self,
        s: &mut R,
    ) -> Result<Message> {
        loop {
            let (parsed, parsed_size) = match crate::codec::parse_message(&self.buffer[..self.have])
            {
                Ok(r) => r,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        let res =
                            tokio::io::AsyncReadExt::read(s, &mut self.buffer[self.have..]).await?;
                        if res == 0 {
                            return Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "eof"));
                        }
                        self.have += res;
                        continue;
                    } else {
                        return Err(e);
                    }
                }
            };
            if parsed_size != self.have {
                self.buffer.copy_within(parsed_size..self.have, 0);
            }
            self.have -= parsed_size;
            return Ok(parsed);
        }
    }
    pub fn new() -> Self {
        Self {
            buffer: [0; MAX_SIZE],
            have: 0,
        }
    }
}

impl Default for DecodeContext {
    fn default() -> Self {
        Self::new()
    }
}
