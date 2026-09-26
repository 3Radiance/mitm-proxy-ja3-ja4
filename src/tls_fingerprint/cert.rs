use anyhow::Result;
use moka::sync::Cache;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

pub type BoringCertPair = (btls::x509::X509, btls::pkey::PKey<btls::pkey::Private>);

pub struct MitmCa {
    ca_cert: Certificate,
    ca_keypair: KeyPair,
    cache: Cache<String, Arc<BoringCertPair>>,
}

impl MitmCa {
    pub fn load_or_create(cert: &str, key: &str) -> Result<Self> {
        let cert_path = Path::new(cert);
        let key_path = Path::new(key);

        let (ca_cert, ca_keypair) = if cert_path.exists() && key_path.exists() {
            let _cert_pem = std::fs::read_to_string(cert_path)?;
            let key_pem = std::fs::read_to_string(key_path)?;
            let keypair = KeyPair::from_pem(&key_pem)?;

            let cert = Self::build_ca_certificate(&keypair)?;

            println!("[CA] Loaded existing MITM CA from disk");
            (cert, keypair)
        } else {
            println!("[CA] CA files not found, generating new MITM CA...");
            let keypair = KeyPair::generate()?;
            let cert = Self::build_ca_certificate(&keypair)?;

            std::fs::write(cert_path, cert.pem())?;
            Self::write_key_secure(key_path, &keypair.serialize_pem())?;

            (cert, keypair)
        };

        let cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_idle(Duration::from_secs(3600))
            .build();

        Ok(Self {
            ca_cert,
            ca_keypair,
            cache,
        })
    }

    fn write_key_secure(path: &Path, pem: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(pem.as_bytes())?;
        Ok(())
    }

    fn build_ca_certificate(keypair: &KeyPair) -> Result<Certificate> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "MITM CA");

        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

        Ok(params.self_signed(keypair)?)
    }

    pub fn get_or_issue_cert(&self, domain: &str) -> Result<Arc<BoringCertPair>> {
        let cert_pair = self
            .cache
            .try_get_with(domain.to_string(), || {
                println!("[CA] Issuing cert for {}", domain);
                let (cert_pem, key_pem) = self.issue_cert_for_domain(domain)?;

                let x509 = btls::x509::X509::from_pem(cert_pem.as_bytes())?;
                let pkey = btls::pkey::PKey::private_key_from_pem(key_pem.as_bytes())?;

                Ok::<_, anyhow::Error>(Arc::new((x509, pkey)))
            })
            .map_err(|e| anyhow::anyhow!("[CA] Failed to get or issue cert: {e}"))?;

        Ok(cert_pair)
    }

    fn issue_cert_for_domain(&self, domain: &str) -> Result<(String, String)> {
        let cert_keypair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![domain.to_string()])?;

        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(1);
        params.subject_alt_names = vec![SanType::DnsName(domain.to_string().try_into()?)];

        let cert = params.signed_by(&cert_keypair, &self.ca_cert, &self.ca_keypair)?;

        Ok((cert.pem(), cert_keypair.serialize_pem()))
    }
}
