use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::Arc;

use crate::config::TcpConfig;

const TABLE: &str = "mangle";
const CHAIN: &str = "POSTROUTING";

pub fn apply_auto_iptables(
    default: Arc<TcpConfig>,
    tcp_domains: HashMap<u32, Arc<TcpConfig>>,
) -> Result<()> {
    if !default.auto_iptables {
        crate::log_tag!(info, "IPT", "auto_iptables=off, skipping");
        return Ok(());
    }

    let qsyn = default
        .qnum_syn
        .ok_or_else(|| anyhow::anyhow!("qnum_syn is not set"))?;
    let qtcp = default
        .qnum_tcp
        .ok_or_else(|| anyhow::anyhow!("qnum_tcp is not set"))?;
    if qsyn == qtcp {
        return Err(anyhow::anyhow!("qnum_syn and qnum_tcp must be different"));
    }

    let marks = collect_marks(default, &tcp_domains);
    if marks.is_empty() {
        crate::log_tag!(warn, "IPT", "no fwmarks found, nothing to apply");
        return Ok(());
    }

    for mark in marks {
        ensure_mark_rules(mark, qsyn, qtcp)?;
    }
    Ok(())
}

pub fn remove_auto_iptables(
    default: Arc<TcpConfig>,
    tcp_domains: HashMap<u32, Arc<TcpConfig>>,
) -> Result<()> {
    if !default.auto_iptables {
        return Ok(());
    }
    let (Some(qsyn), Some(qtcp)) = (default.qnum_syn, default.qnum_tcp) else {
        return Ok(());
    };

    for mark in collect_marks(default, &tcp_domains) {
        for (qnum, syn) in [(qsyn, true), (qtcp, false)] {
            for bin in ["iptables", "ip6tables"] {
                let mark_s = mark.to_string();
                let qnum_s = qnum.to_string();
                loop {
                    match Command::new(bin)
                        .args(build_args(
                            "-D",
                            None,
                            mark_s.as_str(),
                            qnum_s.as_str(),
                            syn,
                        ))
                        .output()
                    {
                        Ok(out) if out.status.success() => continue,
                        _ => break,
                    }
                }
            }
        }
    }
    Ok(())
}

fn collect_marks(default: Arc<TcpConfig>, tcp_domains: &HashMap<u32, Arc<TcpConfig>>) -> Vec<u32> {
    let mut marks: HashSet<u32> = HashSet::new();
    if let Some(m) = default.mark {
        marks.insert(m);
    }
    if !tcp_domains.is_empty() {
        marks.extend(tcp_domains.keys().copied());
    }
    let mut marks: Vec<u32> = marks.into_iter().collect();
    marks.sort_unstable();
    marks
}

fn ensure_mark_rules(mark: u32, qsyn: u16, qtcp: u16) -> Result<()> {
    for (qnum, syn) in [(qsyn, true), (qtcp, false)] {
        ensure_one("iptables", mark, qnum, syn, true)?;
        ensure_one("ip6tables", mark, qnum, syn, false)?;
    }
    Ok(())
}

fn ensure_one(bin: &str, mark: u32, qnum: u16, syn: bool, strict: bool) -> Result<()> {
    let mark_s = mark.to_string();
    let qnum_s = qnum.to_string();

    loop {
        match Command::new(bin)
            .args(build_args(
                "-D",
                None,
                mark_s.as_str(),
                qnum_s.as_str(),
                syn,
            ))
            .output()
        {
            Ok(out) if out.status.success() => continue,
            Ok(_) => break,
            Err(e) if !strict => {
                crate::log_tag!(debug, "IPT", "{} not available, skip: {}", bin, e);
                return Ok(());
            }
            Err(e) => {
                return Err(anyhow::anyhow!("{bin} -D failed: {e}").context("iptables delete"));
            }
        }
    }

    crate::log_tag!(
        info,
        "IPT",
        "{} -I mark={} qnum={} syn={}",
        bin,
        mark,
        qnum,
        syn
    );
    match Command::new(bin)
        .args(build_args(
            "-I",
            Some("1"),
            mark_s.as_str(),
            qnum_s.as_str(),
            syn,
        ))
        .output()
    {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => {
            let err = anyhow::anyhow!("{bin} -I failed: {}", String::from_utf8_lossy(&out.stderr));
            if strict {
                Err(err)
            } else {
                crate::log_tag!(warn, "IPT", "{:#}", err);
                Ok(())
            }
        }
        Err(e) if !strict => {
            crate::log_tag!(warn, "IPT", "{} -I failed: {}", bin, e);
            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("{bin} -I failed: {e}").context("iptables apply")),
    }
}

fn build_args<'a>(
    action: &'a str,
    pos: Option<&'a str>,
    mark: &'a str,
    qnum: &'a str,
    syn: bool,
) -> Vec<&'a str> {
    let mut args = vec!["-t", TABLE, action, CHAIN];
    if let Some(p) = pos {
        args.push(p);
    }
    args.push("-p");
    args.push("tcp");
    if !syn {
        args.push("!");
    }
    args.extend_from_slice(&[
        "--syn",
        "-m",
        "mark",
        "--mark",
        mark,
        "-j",
        "NFQUEUE",
        "--queue-num",
        qnum,
        "--queue-bypass",
    ]);
    args
}
