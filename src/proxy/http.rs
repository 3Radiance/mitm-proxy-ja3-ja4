use anyhow::Result;
use crate::proxy::tcp::{ConnectionStatus, HTTP_403_FORBIDDEN};
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::TcpStream};

#[derive(Debug)]
#[allow(dead_code)]
pub struct HttpPacket {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub header_len: usize,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct HttpPacketRes {
    pub code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub header_len: usize,
}

pub enum ParseResult<T> {
    Complete(T),
    Partial,
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

    pub fn parse(buf: &[u8]) -> Result<ParseResult<HttpPacket>> {
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

    pub async fn check_method(
        packet: Arc<HttpPacket>,
        mut client: TcpStream,
    ) -> Result<ConnectionStatus> {
        if packet.method != "CONNECT" {
            let peer_addr = client
                .peer_addr()
                .map(|a| a.to_string())
                .unwrap_or_else(|_| "unknown".to_string());

            client.write_all(HTTP_403_FORBIDDEN).await?;
            client.flush().await?;

            let log_msg = format!(
                "Rejected non-CONNECT request: method: '{}', path: '{}', from: {}, headers: {:#?}",
                packet.method,
                packet.path,
                peer_addr,
                packet
                    .headers
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<String>>()
            );

            return Ok(ConnectionStatus::Failure(log_msg));
        }
        Ok(ConnectionStatus::Success(client))
    }
}

impl HttpPacketRes {
    pub fn parse(buf: &[u8]) -> Result<ParseResult<HttpPacketRes>> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut resp = httparse::Response::new(&mut headers);

        match resp.parse(buf)? {
            httparse::Status::Complete(len) => {
                let parsed = HttpPacketRes {
                    code: resp.code.unwrap_or(0),
                    reason: resp.reason.unwrap_or("").to_string(),
                    headers: resp
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
}
