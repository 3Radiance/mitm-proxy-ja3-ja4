use anyhow::Result;
use hudsucker::{
    async_trait::async_trait,
    certificate_authority::RcgenAuthority,
    hyper::{ header,Body, Request, Response},
    HttpContext, HttpHandler, Proxy, RequestOrResponse,
};
use hyper::service::Service;
use hyper::{client::connect::Connection, Uri};
use rustls::{Certificate, PrivateKey};
use std::fs;
use std::future::Future;
use std::net::TcpListener;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

const PROXY_LISTEN: &str = "127.0.0.1:8001";
const SOCKS5_UPSTREAM: &str = "127.0.0.1:10808";
const CA_CERT_PATH: &str = "ca-cert.pem";
const CA_KEY_PATH: &str = "ca-key.pem";

#[derive(Clone)]
struct MitmHandler;

#[async_trait]
impl HttpHandler for MitmHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        mut req: Request<Body>,
    ) -> RequestOrResponse {
        let is_mobile = if let Some(ua) = req.headers().get(header::USER_AGENT) {
            let ua_str = ua.to_str().unwrap_or_default().to_lowercase();
            ua_str.contains("android") || ua_str.contains("iphone") || ua_str.contains("mobile")
        } else {
            false
        };

        if is_mobile {
      
            req.headers_mut().insert(
                header::USER_AGENT,
                "Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0"
                    .parse()
                    .unwrap(),
            );
            req.headers_mut().insert(
                "sec-ch-ua-mobile",
                "?1".parse().unwrap(),
            );
        } else {
          
            req.headers_mut().insert(
                header::USER_AGENT,
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
                    .parse()
                    .unwrap(),
            );
            req.headers_mut().insert(
                "sec-ch-ua-mobile",
                "?0".parse().unwrap(),
            );
        }

        req.into()
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        res
    }
}

#[derive(Clone)]
struct SocksConnector {
    proxy: String,
}

impl Service<Uri> for SocksConnector {
    type Response = SocksConnection;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let proxy = self.proxy.clone();
        Box::pin(async move {
            let host = dst.host().ok_or("missing host")?;
            let port = dst.port_u16().unwrap_or(443);
            let stream = Socks5Stream::<TcpStream>::connect(proxy.as_str(), (host, port)).await?;
            Ok(SocksConnection(stream))
        })
    }
}

struct SocksConnection(Socks5Stream<TcpStream>);

impl Connection for SocksConnection {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new()
    }
}

impl AsyncRead for SocksConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for SocksConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // --- Генерация или загрузка CA ---
    let (private_key, ca_cert) = if Path::new(CA_CERT_PATH).exists() && Path::new(CA_KEY_PATH).exists() {
        println!("Loading existing CA from {} and {}...", CA_CERT_PATH, CA_KEY_PATH);
        let cert_pem = fs::read_to_string(CA_CERT_PATH)?;
        let key_pem = fs::read_to_string(CA_KEY_PATH)?;
        
        // Парсим PEM в DER для rustls
        let cert_der = parse_pem_cert(&cert_pem)?;
        let key_der = parse_pem_key(&key_pem)?;
        
        (PrivateKey(key_der), Certificate(cert_der))
    } else {
        println!("Generating new CA...");
        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = rcgen::CertificateParams::new(vec![]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_pair = Some(key_pair); // <-- ВОТ ЭТО ДОБАВЬ

        let cert = rcgen::Certificate::from_params(params)?;

        let cert_pem = cert.serialize_pem()?;
        let key_pem = cert.get_key_pair().serialize_pem(); // <-- И ВОТ ЭТО

        fs::write(CA_CERT_PATH, &cert_pem)?;
        fs::write(CA_KEY_PATH, &key_pem)?;

        println!("=== CA SAVED ===");
        println!("Certificate: {}", CA_CERT_PATH);
        println!("Private key: {}", CA_KEY_PATH);
        println!("IMPORT ca-cert.pem INTO FIREFOX NOW!");
        println!("================");

        let private_key = PrivateKey(cert.get_key_pair().serialize_der());
        let ca_cert = Certificate(cert.serialize_der()?);
        (private_key, ca_cert)
    };

    let ca = RcgenAuthority::new(private_key, ca_cert, 1000)?;

    // --- TLS + SOCKS5 + Client ---
    let tls_config = build_custom_ja3_tls_config();
    let socks = SocksConnector {
        proxy: SOCKS5_UPSTREAM.to_string(),
    };
    let https: hyper_rustls::HttpsConnector<SocksConnector> = (socks, tls_config).into();

    let mut client_builder = hudsucker::hyper::Client::builder();
    client_builder.http2_only(false);
    client_builder.http2_initial_stream_window_size(65535);
    client_builder.http2_initial_connection_window_size(15663105);
    client_builder.http2_keep_alive_interval(Duration::from_secs(20));
    client_builder.http2_keep_alive_timeout(Duration::from_secs(10));
    let client = client_builder.build(https);

    // --- Proxy ---
    let listener = TcpListener::bind(PROXY_LISTEN)?;
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_client(client)
        .with_ca(ca)
        .with_http_handler(MitmHandler)
        .build();

    println!("MITM Proxy active on   {}", PROXY_LISTEN);
    println!("Upstream SOCKS5      {}", SOCKS5_UPSTREAM);

    if let Err(e) = proxy
        .start(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
    {
        eprintln!("Proxy error: {}", e);
    }

    Ok(())
}

fn parse_pem_cert(pem: &str) -> Result<Vec<u8>> {
    for line in pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            let start = pem.find(line).unwrap();
            let end = pem[start..].find("END CERTIFICATE").unwrap() + start + "END CERTIFICATE".len() + 5;
            let block = &pem[start..end];
            let der = pem::parse(block)?;
            return Ok(der.contents().to_vec());  // <-- скобки!
        }
    }
    anyhow::bail!("No certificate found in PEM")
}

fn parse_pem_key(pem: &str) -> Result<Vec<u8>> {
    for line in pem.lines() {
        if line.contains("BEGIN PRIVATE KEY") || line.contains("BEGIN EC PRIVATE KEY") {
            let start = pem.find(line).unwrap();
            let end_marker = if pem[start..].contains("END PRIVATE KEY") {
                "END PRIVATE KEY"
            } else {
                "END EC PRIVATE KEY"
            };
            let end = pem[start..].find(end_marker).unwrap() + start + end_marker.len() + 5;
            let block = &pem[start..end];
            let der = pem::parse(block)?;
            return Ok(der.contents().to_vec());  // <-- скобки!
        }
    }
    anyhow::bail!("No private key found in PEM")
}

fn build_custom_ja3_tls_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            })
    );

    let custom_cipher_suites = vec![
        rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ];

    let mut config = rustls::ClientConfig::builder()
        .with_cipher_suites(&custom_cipher_suites)
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}