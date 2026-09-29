use anyhow::Result;
use etherparse::{NetHeaders, PacketHeaders, TcpOptionElement, TcpOptions, TransportHeader};
use nfq::{Queue, Verdict};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::TcpConfig;

pub async fn start_qnum_syn(
    default: Arc<TcpConfig>,
    tcp_domains: HashMap<u32, Arc<TcpConfig>>,
) -> Result<()> {
    let mut queue = Queue::open()?;
    let qnum = default
        .qnum_syn
        .ok_or_else(|| anyhow::anyhow!("QNUM_SYN is not set"))?;
    crate::log_tag!(info, "NFQUEUE", "Starting qnum_syn: {}", qnum);
    queue.bind(qnum)?;

    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload().to_vec();
        let mark = msg.get_nfmark();

        let config: &TcpConfig = if default.mark.is_some_and(|m| m != mark) {
            tcp_domains.get(&mark).unwrap_or(&default)
        } else {
            &default
        };

        let mut new_packet: Option<Vec<u8>> = None;

        if let Ok(headers) = PacketHeaders::from_ip_slice(&payload) {
            if let Some(NetHeaders::Ipv4(mut ipv4, _)) = headers.net {
                if let Some(TransportHeader::Tcp(mut tcp)) = headers.transport {
                    if tcp.syn && !tcp.ack {
                        if let Some(win) = config.window_size {
                            tcp.window_size = win as u16;
                        }
                        if let Some(ttl) = config.ttl {
                            ipv4.time_to_live = ttl;
                        }
                        ipv4.dont_fragment = config.dont_fragment;

                        tcp.options = build_tcp_options(config, &tcp.options);

                        let tcp_payload = headers.payload.slice().to_vec();

                        let _ = ipv4.set_payload_len(tcp.header_len() + tcp_payload.len());

                        tcp.checksum = tcp
                            .calc_checksum_ipv4(&ipv4, &tcp_payload)
                            .expect("calc tcp checksum");
                        ipv4.header_checksum = ipv4.calc_header_checksum();

                        let mut buf = Vec::with_capacity(ipv4.total_len as usize);
                        ipv4.write(&mut buf).unwrap();
                        tcp.write(&mut buf).unwrap();
                        buf.extend_from_slice(&tcp_payload);
                        new_packet = Some(buf);
                    }
                }
            }
        }

        if let Some(pkt) = new_packet {
            msg.set_payload(pkt);
        }
        msg.set_nfmark(0);
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg)?;
    }
}

fn build_tcp_options(config: &TcpConfig, orig: &TcpOptions) -> TcpOptions {
    let mut orig_mss = None;
    let mut orig_wscale = None;
    let mut orig_ts = None;
    for el in orig.elements_iter().flatten() {
        match el {
            TcpOptionElement::MaximumSegmentSize(v) => orig_mss = Some(v),
            TcpOptionElement::WindowScale(v) => orig_wscale = Some(v),
            TcpOptionElement::Timestamp(a, b) => orig_ts = Some((a, b)),
            _ => {}
        }
    }

    let Some(order) = &config.tcp_options_order else {
        let mut elems = Vec::new();
        let mut mss_patched = false;
        let mut ws_patched = false;
        for el in orig.elements_iter().flatten() {
            match el {
                TcpOptionElement::MaximumSegmentSize(_) if config.mss.is_some() => {
                    elems.push(TcpOptionElement::MaximumSegmentSize(config.mss.unwrap()));
                    mss_patched = true;
                }
                TcpOptionElement::WindowScale(_) if config.window_scale.is_some() => {
                    elems.push(TcpOptionElement::WindowScale(config.window_scale.unwrap()));
                    ws_patched = true;
                }
                TcpOptionElement::Timestamp(..) if !config.timestamp => {}
                other => elems.push(other),
            }
        }
        if !mss_patched {
            if let Some(v) = config.mss {
                elems.push(TcpOptionElement::MaximumSegmentSize(v));
            }
        }
        if !ws_patched {
            if let Some(v) = config.window_scale {
                elems.push(TcpOptionElement::WindowScale(v));
            }
        }
        return TcpOptions::try_from_elements(&elems).unwrap_or_else(|_| orig.clone());
    };

    let mut elems = Vec::with_capacity(order.len());
    for name in order {
        match name.to_ascii_lowercase().as_str() {
            "mss" => {
                if let Some(v) = config.mss.or(orig_mss) {
                    elems.push(TcpOptionElement::MaximumSegmentSize(v));
                }
            }
            "wscale" | "window_scale" | "ws" => {
                if let Some(v) = config.window_scale.or(orig_wscale) {
                    elems.push(TcpOptionElement::WindowScale(v));
                }
            }
            "sack_perm" | "sack" | "sack_ok" | "sack_permitted" => {
                elems.push(TcpOptionElement::SelectiveAcknowledgementPermitted);
            }
            "timestamp" | "ts" | "timestamps" => {
                if config.timestamp {
                    let (a, b) = orig_ts.unwrap_or((0, 0));
                    elems.push(TcpOptionElement::Timestamp(a, b));
                }
            }
            "nop" | "noop" => elems.push(TcpOptionElement::Noop),
            _ => {}
        }
    }
    TcpOptions::try_from_elements(&elems).unwrap_or_else(|_| orig.clone())
}
