use crate::config::*;
use crate::h2_fingerprint::h2::ConnectionData;
use crate::h2_fingerprint::request_body::*;
use crate::h2_fingerprint::response::*;
use crate::h2_fingerprint::upstream::*;

use bytes::Bytes;
use http::Request;
use http2::server::SendResponse;
use http2::RecvStream;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn handle_request(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    upstream_send: Arc<Mutex<http2::client::SendRequest<Bytes>>>,
    proxydata: ConnectionData,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let method = request.method().clone();
    let uri = request.uri().clone();

    println!("[H2] {} {}", method, uri);

    let (req_parts, mut req_body) = request.into_parts();

    let mut upstream_req = Request::builder()
        .method(req_parts.method.clone())
        .uri(req_parts.uri.clone());

    let headers = match proxydata.http2.apply_http_headers(&req_parts.headers) {
        Ok(headers) => headers,
        Err(err) => {
            eprintln!("[H2] apply http headers failed: {err}");
            return Ok(());
        }
    };

    for (name, value) in headers {
        upstream_req = upstream_req.header(name, value);
    }

    let req_is_end_stream = req_body.is_end_stream();

    let end_stream_on_headers = req_is_end_stream && proxydata.http2.end_stream_on_headers;

    let upstream_req = match upstream_req.body(()) {
        Ok(req) => req,
        Err(err) => {
            eprintln!("[H2] request build failed: {err}");
            return Ok(());
        }
    };

    let send_handle = {
        let guard = upstream_send.lock().await;
        guard.clone()
    };

    let mut send_handle = match send_handle.ready().await {
        Ok(s) => s,

        Err(_) => {
            let new_builder = match build_upstream_h2_builder(proxydata.http2.clone()).await {
                Ok(b) => b,
                Err(err) => {
                    eprintln!("[H2] reconnect builder failed: {err:?}");
                    return Ok(());
                }
            };

            let new_remote = match upstream_reconnect(proxydata.clone()).await {
                Ok(r) => r,
                Err(err) => {
                    eprintln!("[H2] upstream reconnect failed: {err:?}");
                    return Ok(());
                }
            };

            let (new_send, new_conn) = match new_builder.handshake::<_, Bytes>(new_remote).await {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("[H2] reconnect handshake failed: {err:?}");
                    return Ok(());
                }
            };

            tokio::spawn(async move {
                if let Err(err) = new_conn.await {
                    eprintln!("[H2] Upstream h2 connection error: {err}");
                }
            });

            let mut guard = upstream_send.lock().await;
            *guard = new_send.clone();

            new_send
        }
    };

    let (upstream_resp, mut req_send_stream) =
        match send_handle.send_request(upstream_req, end_stream_on_headers) {
            Ok(v) => v,
            Err(err) => {
                eprintln!("[H2] send_request failed: {err:?}");
                return Ok(());
            }
        };

    forward_request_body(
        &mut req_body,
        &mut req_send_stream,
        req_is_end_stream,
        end_stream_on_headers,
    )
    .await?;

    let response = match upstream_resp.await {
        Ok(response) => response,
        Err(err) => {
            eprintln!("[H2] response failed: {err:?}");
            return Ok(());
        }
    };

    forward_response(response, &mut respond).await?;

    Ok(())
}
