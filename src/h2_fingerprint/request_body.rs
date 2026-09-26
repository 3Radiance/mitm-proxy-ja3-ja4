use anyhow::Result;
use bytes::Bytes;

pub async fn forward_request_body(
    req_body: &mut http2::RecvStream,
    req_send_stream: &mut http2::SendStream<Bytes>,
    req_is_end_stream: bool,
    end_stream_on_headers: bool,
) -> Result<()> {
    if req_is_end_stream {
        if !end_stream_on_headers {
            req_send_stream.send_data(Bytes::new(), true)?;
        }

        return Ok(());
    }

    let mut req_flow = req_body.flow_control().clone();
    let mut pending: Option<Bytes> = None;

    while let Some(chunk) = req_body.data().await {
        let chunk = chunk?;

        if !chunk.is_empty() {
            req_flow.release_capacity(chunk.len())?;

            if let Some(prev) = pending.take() {
                req_send_stream.send_data(prev, false)?;
            }

            pending = Some(chunk);
        }
    }

    let trailers = req_body.trailers().await?;

    if let Some(last) = pending {
        let end_stream = trailers.is_none();

        req_send_stream.send_data(last, end_stream)?;
    } else if trailers.is_none() {
        req_send_stream.send_data(Bytes::new(), true)?;
    }

    if let Some(trailers) = trailers {
        req_send_stream.send_trailers(trailers)?;
    }

    Ok(())
}
