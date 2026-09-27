use anyhow::Result;
use bytes::Bytes;
use http::Response;
use http2::server::SendResponse;
use http2::RecvStream;

pub async fn forward_response(
    response: Response<RecvStream>,
    respond: &mut SendResponse<Bytes>,
) -> Result<()> {
    let (head, mut body) = response.into_parts();

    let resp_is_end_stream = body.is_end_stream();

    let resp = Response::from_parts(head, ());

    let mut send_stream = match respond.send_response(resp, resp_is_end_stream) {
        Ok(stream) => stream,

        Err(err) => {
            crate::log_tag!(error, "H2", "Send response failed: {err:?}");
            return Ok(());
        }
    };

    if !resp_is_end_stream {
        let mut flow = body.flow_control().clone();

        while let Some(chunk) = body.data().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,

                Err(err) => {
                    crate::log_tag!(error, "H2", "Upstream body failed: {err:?}");
                    return Ok(());
                }
            };

            let len = chunk.len();
            let is_eos = body.is_end_stream();

            if len > 0 || is_eos {
                if let Err(err) = send_stream.send_data(chunk, is_eos) {
                    crate::log_tag!(error, "H2", "Downstream send_data failed: {err:?}");
                    return Ok(());
                }

                if len > 0 {
                    if let Err(err) = flow.release_capacity(len) {
                        crate::log_tag!(error, "H2", "Release capacity failed: {err:?}");
                        return Ok(());
                    }
                }
            }
        }

        if let Ok(Some(trailers)) = body.trailers().await {
            let _ = send_stream.send_trailers(trailers);
        }
    }

    Ok(())
}
