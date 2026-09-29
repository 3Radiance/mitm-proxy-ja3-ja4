use anyhow::Result;
use etherparse::{NetHeaders, PacketHeaders, TransportHeader};
use nfq::{Queue, Verdict};
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::TcpConfig;

pub async fn start_qnum_tcp(
    default: Arc<TcpConfig>,
    tcp_domains: HashMap<u32, Arc<TcpConfig>>,
) -> Result<()> {
    let mut queue = Queue::open()?;
    let qnum = default
        .qnum_tcp
        .ok_or_else(|| anyhow::anyhow!("QNUM_TCP is not set"))?;
    crate::log_tag!(info, "NFQUEUE", "Starting qnum_tcp: {}", qnum);
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
            match headers.net {
                Some(NetHeaders::Ipv4(mut ipv4, _)) => {
                    if let Some(TransportHeader::Tcp(mut tcp)) = headers.transport {
                        let mut changed = false;

                        if let Some(ttl) = config.ttl {
                            if ipv4.time_to_live != ttl {
                                ipv4.time_to_live = ttl;
                                changed = true;
                            }
                        }
                        if ipv4.dont_fragment != config.dont_fragment {
                            ipv4.dont_fragment = config.dont_fragment;
                            changed = true;
                        }

                        if changed {
                            let tcp_payload = headers.payload.slice().to_vec();
                            if let Ok(csum) = tcp.calc_checksum_ipv4(&ipv4, &tcp_payload) {
                                tcp.checksum = csum;
                            }
                            ipv4.header_checksum = ipv4.calc_header_checksum();

                            let mut buf = Vec::with_capacity(ipv4.total_len as usize);
                            ipv4.write(&mut buf).unwrap();
                            tcp.write(&mut buf).unwrap();
                            buf.extend_from_slice(&tcp_payload);
                            new_packet = Some(buf);
                        }
                    }
                }
                Some(NetHeaders::Ipv6(mut ipv6, _)) => {
                    if let Some(TransportHeader::Tcp(mut tcp)) = headers.transport {
                        if let Some(ttl) = config.ttl {
                            if ipv6.hop_limit != ttl {
                                ipv6.hop_limit = ttl;
                                let tcp_payload = headers.payload.slice().to_vec();
                                if let Ok(csum) = tcp.calc_checksum_ipv6(&ipv6, &tcp_payload) {
                                    tcp.checksum = csum;
                                }
                                let mut buf = Vec::with_capacity(ipv6.payload_length as usize + 40);
                                ipv6.write(&mut buf).unwrap();
                                tcp.write(&mut buf).unwrap();
                                buf.extend_from_slice(&tcp_payload);
                                new_packet = Some(buf);
                            }
                        }
                    }
                }
                _ => {}
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
