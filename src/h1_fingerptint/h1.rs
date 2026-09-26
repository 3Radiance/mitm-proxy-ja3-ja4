use anyhow::Result;
use crate::h2_fingerprint::h2::ConnectionData;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_btls::SslStream;

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

    tokio::task::spawn(async move { if let Err(_err) = conn.await {} });

    let service = service_fn(move |req: http::Request<Incoming>| {
        let sender = sender.clone();
        let proxydata = Arc::clone(&proxydata);

        async move {
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
        .await?;

    Ok(())
}
