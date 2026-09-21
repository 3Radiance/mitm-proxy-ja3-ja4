use std::error::Error;

#[derive(Debug)]
#[allow(dead_code)]
pub struct HttpPacket {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub header_len: usize,
}

impl HttpPacket {
    pub fn get_header(&self, name: &str) -> Option<&str> {
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case(name) {
                return Some(v.as_str());
            }
        }
        None
    }
}

pub enum ParseResult {
    Complete(HttpPacket),
    Partial,
}

pub fn parse(buf: &[u8]) -> Result<ParseResult, Box<dyn Error + Send + Sync>> {
    let mut headers = [httparse::EMPTY_HEADER; 64];

    let mut req = httparse::Request::new(&mut headers[..]);
    match req.parse(buf)? {
        httparse::Status::Complete(len) => {
            let parsed = HttpPacket {
                method: req.method.unwrap_or("").to_string(),
                path: req.path.unwrap_or("").to_string(),
                headers: req
                    .headers
                    .iter()
                    .map(|h| {
                        (
                            h.name.to_string(),
                            String::from_utf8_lossy(h.value).to_string(),
                        )
                    })
                    .collect(),
                header_len: len,
            };
            Ok(ParseResult::Complete(parsed))
        }
        httparse::Status::Partial => Ok(ParseResult::Partial),
    }
}
