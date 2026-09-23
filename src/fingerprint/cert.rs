use dashmap::DashMap;
use rcgen::{BasicConstraints, Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use time::OffsetDateTime;

pub type BoringCertPair = (btls::x509::X509, btls::pkey::PKey<btls::pkey::Private>);

pub struct MitmCa {
    ca_cert: Certificate,
    ca_keypair: KeyPair,
    cache: DashMap<String, BoringCertPair>,
}

impl MitmCa {
    pub fn load_or_create(
        cert: &str,
        key: &str,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let cert_path = Path::new(cert);
        let key_path = Path::new(key);

        let (ca_cert, ca_keypair) = if cert_path.exists() && key_path.exists() {
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

        Ok(Self {
            ca_cert,
            ca_keypair,
            cache: DashMap::new(),
        })
    }

    fn write_key_secure(
        path: &Path,
        pem: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(pem.as_bytes())?;
        Ok(())
    }

    fn build_ca_certificate(
        keypair: &KeyPair,
    ) -> Result<Certificate, Box<dyn std::error::Error + Send + Sync>> {
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "MITM CA");

        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(365 * 10);

        Ok(params.self_signed(keypair)?)
    }

    pub fn get_or_issue_cert(
        &self,
        domain: &str,
    ) -> Result<BoringCertPair, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(cached) = self.cache.get(domain) {
            println!("[CA] Found cached cert for {}", domain);
            return Ok(cached.value().clone());
        }

        let (cert_pem, key_pem) = self.issue_cert_for_domain(domain)?;
        println!("[CA] Issuing cert for {}", domain);

        let x509 = btls::x509::X509::from_pem(cert_pem.as_bytes())?;
        let pkey = btls::pkey::PKey::private_key_from_pem(key_pem.as_bytes())?;

        let cert_pair = (x509, pkey);
        self.cache.insert(domain.to_string(), cert_pair.clone());

        Ok(cert_pair)
    }

    fn issue_cert_for_domain(
        &self,
        domain: &str,
    ) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
        let cert_keypair = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![domain.to_string()])?;

        params.not_before = OffsetDateTime::now_utc();
        params.not_after = OffsetDateTime::now_utc() + time::Duration::days(1);
        params.subject_alt_names = vec![SanType::DnsName(domain.to_string().try_into()?)];

        let cert = params.signed_by(&cert_keypair, &self.ca_cert, &self.ca_keypair)?;

        Ok((cert.pem(), cert_keypair.serialize_pem()))
    }
}
