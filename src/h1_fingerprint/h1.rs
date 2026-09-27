use crate::h2_fingerprint::h2::ConnectionData;
use anyhow::Result;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_btls::SslStream;

fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    let has_upgrade = headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    if !has_upgrade {
        return false;
    }
    headers
        .get(http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false)
}

pub async fn handle_h1(
    client_stream: SslStream<TcpStream>,
    remote_stream: SslStream<TcpStream>,
    proxydata: ConnectionData,
) -> Result<()> {
    let proxydata = Arc::new(&proxydata);
    let (sender, conn) = hyper::client::conn::http1::Builder::new()
        .title_case_headers(true)
        .handshake(TokioIo::new(remote_stream))
        .await?;

    let sender = Arc::new(Mutex::new(sender));

    tokio::task::spawn(async move {
        if let Err(_err) = conn.with_upgrades().await {}
    });

    let service = service_fn(move |mut req: http::Request<Incoming>| {
        let sender = sender.clone();
        let proxydata = Arc::clone(&proxydata);

        async move {
            let is_ws = is_websocket_upgrade(req.headers());
            crate::log_tag!(
                info,
                "H1",
                "{} {}{}",
                req.method(),
                req.uri(),
                if is_ws { " [ws-upgrade]" } else { "" }
            );

            if is_ws {
                let client_upgrade = hyper::upgrade::on(&mut req);
                let (parts, body) = req.into_parts();

                let new_headers = proxydata.http1.apply_http_headers(&parts.headers)?;

                let mut new_req = http::Request::new(body);
                *new_req.method_mut() = parts.method;
                *new_req.uri_mut() = parts.uri;
                *new_req.version_mut() = parts.version;

                let headers_mut = new_req.headers_mut();
                headers_mut.clear();

                for (name_str, val) in new_headers {
                    if let Ok(name) = http::header::HeaderName::from_bytes(name_str.as_bytes()) {
                        headers_mut.append(name, val);
                    }
                }

                for key in [
                    http::header::UPGRADE,
                    http::header::CONNECTION,
                    http::header::SEC_WEBSOCKET_KEY,
                    http::header::SEC_WEBSOCKET_VERSION,
                ] {
                    if !headers_mut.contains_key(&key) {
                        if let Some(v) = parts.headers.get(&key) {
                            headers_mut.insert(key, v.clone());
                        }
                    }
                }
                if !headers_mut.contains_key(http::header::SEC_WEBSOCKET_PROTOCOL) {
                    if let Some(v) = parts.headers.get(http::header::SEC_WEBSOCKET_PROTOCOL) {
                        headers_mut.insert(http::header::SEC_WEBSOCKET_PROTOCOL, v.clone());
                    }
                }

                let mut resp = {
                    let mut sender_locked = sender.lock().await;
                    sender_locked.send_request(new_req).await?
                };

                if resp.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                    let server_upgrade = hyper::upgrade::on(&mut resp);
                    tokio::spawn(async move {
                        match (client_upgrade.await, server_upgrade.await) {
                            (Ok(client), Ok(server)) => {
                                let mut client_io = TokioIo::new(client);
                                let mut server_io = TokioIo::new(server);
                                match tokio::io::copy_bidirectional(&mut client_io, &mut server_io)
                                    .await
                                {
                                    Ok((a, b)) => {
                                        crate::log_tag!(
                                            info,
                                            "H1",
                                            "WS tunnel closed a->b={} b->a={}",
                                            a,
                                            b
                                        );
                                    }
                                    Err(e) => {
                                        crate::log_tag!(warn, "H1", "WS tunnel error: {e:?}");
                                    }
                                }
                            }
                            (a, b) => {
                                crate::log_tag!(
                                    warn,
                                    "H1",
                                    "WS upgrade failed client_ok={} server_ok={}",
                                    a.is_ok(),
                                    b.is_ok()
                                );
                            }
                        }
                    });
                } else {
                    crate::log_tag!(warn, "H1", "WS upgrade rejected: {}", resp.status());
                }

                return Ok::<_, anyhow::Error>(resp);
            }

            let (parts, body) = req.into_parts();

            let new_headers = proxydata.http1.apply_http_headers(&parts.headers)?;

            let mut new_req = http::Request::new(body);
            *new_req.method_mut() = parts.method;
            *new_req.uri_mut() = parts.uri;
            *new_req.version_mut() = parts.version;

            let headers_mut = new_req.headers_mut();
            headers_mut.clear();

            for (name_str, val) in new_headers {
                if let Ok(name) = http::header::HeaderName::from_bytes(name_str.as_bytes()) {
                    headers_mut.append(name, val);
                }
            }

            let mut sender_locked = sender.lock().await;
            let resp = sender_locked.send_request(new_req).await?;

            Ok::<_, anyhow::Error>(resp)
        }
    });

    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(client_stream), service)
        .with_upgrades()
        .await?;

    Ok(())
}
