// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

pub use deno_native_certs;
pub use rustls;
pub use rustls_pemfile;
pub use rustls_tokio_stream;
pub use webpki;
pub use webpki_roots;

use deno_core::anyhow::anyhow;
use deno_core::error::custom_error;
use deno_core::error::AnyError;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs1KeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::TrustAnchor;
use rustls::pki_types::UnixTime;
use rustls::ClientConfig;
use rustls::DigitallySignedStruct;
use rustls::Error;
use rustls::RootCertStore;
use rustls_pemfile::certs;
use rustls_pemfile::pkcs8_private_keys;
use rustls_pemfile::rsa_private_keys;
use serde::Deserialize;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Cursor;
use std::sync::Arc;

/// Lazily resolves the root cert store.
///
/// This was done because the root cert store is not needed in all cases
/// and takes a bit of time to initialize.
pub trait RootCertStoreProvider: Send + Sync {
  fn get_or_try_init(&self) -> Result<&RootCertStore, AnyError>;
}

// This extension has no runtime apis, it only exports some shared native functions.
deno_core::extension!(deno_tls);

#[derive(Debug)]
pub struct NoCertificateVerification {
  pub certs: Vec<String>,
  default_verifier: Arc<WebPkiServerVerifier>,
}

impl NoCertificateVerification {
  pub fn new(certs: Vec<String>) -> Result<Self, Error> {
    let root_store = create_default_root_cert_store();
    let default_verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
      .build()
      .map_err(|err| match err {
        rustls::server::VerifierBuilderError::NoRootAnchors => {
          Error::NoCertificatesPresented
        }
        rustls::server::VerifierBuilderError::InvalidCrl(err) => {
          Error::InvalidCertRevocationList(err)
        }
        _ => Error::General("Unknown error".to_string()),
      })?;

    Ok(Self {
      certs,
      default_verifier,
    })
  }
}

impl ServerCertVerifier for NoCertificateVerification {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    server_name: &ServerName<'_>,
    ocsp_response: &[u8],
    now: UnixTime,
  ) -> Result<ServerCertVerified, Error> {
    if self.certs.is_empty() {
      return Ok(ServerCertVerified::assertion());
    }
    let dns_name_or_ip_address = match server_name {
      ServerName::DnsName(dns_name) => dns_name.as_ref().to_owned(),
      ServerName::IpAddress(ip_address) => match ip_address {
        rustls::pki_types::IpAddr::V4(ipv4) => {
          let vals = ipv4.as_ref();
          format!("{}.{}.{}.{}", vals[0], vals[1], vals[2], vals[3])
        }
        rustls::pki_types::IpAddr::V6(ipv6) => {
          let vals = ipv6.as_ref();
          format!(
            "{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}:{:x}{:x}",
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
            vals[8], vals[9], vals[10], vals[11], vals[12], vals[13], vals[14], vals[15]
          )
        }
      },
      _ => {
        // NOTE(bartlomieju): `ServerName` is a non-exhaustive enum
        // so we have this catch all errors here.
        return Err(Error::General("Unknown `ServerName` variant".to_string()));
      }
    };
    if self.certs.contains(&dns_name_or_ip_address) {
      Ok(ServerCertVerified::assertion())
    } else {
      self.default_verifier.verify_server_cert(
        end_entity,
        intermediates,
        server_name,
        ocsp_response,
        now,
      )
    }
  }

  fn verify_tls12_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, Error> {
    if self.certs.is_empty() {
      return Ok(HandshakeSignatureValid::assertion());
    }
    filter_invalid_encoding_err(
      self
        .default_verifier
        .verify_tls12_signature(message, cert, dss),
    )
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, Error> {
    if self.certs.is_empty() {
      return Ok(HandshakeSignatureValid::assertion());
    }
    filter_invalid_encoding_err(
      self
        .default_verifier
        .verify_tls13_signature(message, cert, dss),
    )
  }

  fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
    let provider = rustls::crypto::ring::default_provider();
    provider
      .signature_verification_algorithms
      .supported_schemes()
  }
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(default)]
pub struct Proxy {
  pub url: String,
  pub basic_auth: Option<BasicAuth>,
}

#[derive(Deserialize, Default, Debug, Clone)]
#[serde(default)]
pub struct BasicAuth {
  pub username: String,
  pub password: String,
}

pub fn create_default_root_cert_store() -> RootCertStore {
  let mut root_cert_store = RootCertStore::empty();

  root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
    TrustAnchor {
      subject: ta.subject.into(),
      subject_public_key_info: ta.spki.into(),
      name_constraints: ta.name_constraints.map(|nc| nc.into()),
    }
  }));

  // // TODO(@justinmchase): Consider also loading the system keychain here
  // root_cert_store.add_parsable_certificates(.map(
  //   |ta| {
  //     rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
  //       ta.subject,
  //       ta.spki,
  //       ta.name_constraints,
  //     )
  //   },
  // ));
  root_cert_store
}

pub enum SocketUse {
  /// General SSL: No ALPN
  GeneralSsl,
  /// HTTP: h1 and h2
  Http,
  /// http/1.1 only
  Http1Only,
  /// http/2 only
  Http2Only,
}

pub fn create_client_config(
  root_cert_store: Option<RootCertStore>,
  ca_certs: Vec<Vec<u8>>,
  unsafely_ignore_certificate_errors: Option<Vec<String>>,
  client_cert_chain_and_key: Option<(String, String)>,
  socket_use: SocketUse,
) -> Result<ClientConfig, AnyError> {
  let maybe_cert_chain_and_key =
    if let Some((cert_chain, private_key)) = client_cert_chain_and_key {
      // The `remove` is safe because load_private_keys checks that there is at least one key.
      let private_key = load_private_keys(private_key.as_bytes())?.remove(0);
      let cert_chain = load_certs(&mut cert_chain.as_bytes())?;
      Some((cert_chain, private_key))
    } else {
      None
    };

  //ServerCertVerifierBuilder::

  if let Some(ic_allowlist) = unsafely_ignore_certificate_errors {
    let client_config = ClientConfig::builder()
      .dangerous()
      .with_custom_certificate_verifier(Arc::new(
        NoCertificateVerification::new(ic_allowlist)?,
      ));

    // NOTE(bartlomieju): this if/else is duplicated at the end of the body of this function.
    // However it's not really feasible to deduplicate it as the `client_config` instances
    // are not type-compatible - one wants "client cert", the other wants "transparency policy
    // or client cert".
    let mut client =
      if let Some((cert_chain, private_key)) = maybe_cert_chain_and_key {
        client_config
          .with_client_auth_cert(cert_chain, private_key)
          .expect("invalid client key or certificate")
      } else {
        client_config.with_no_client_auth()
      };

    add_alpn(&mut client, socket_use);
    return Ok(client);
  }

  let client_config = ClientConfig::builder().with_root_certificates({
    let mut root_cert_store =
      root_cert_store.unwrap_or_else(create_default_root_cert_store);
    // If custom certs are specified, add them to the store
    for cert in ca_certs {
      let reader = &mut BufReader::new(Cursor::new(cert));
      // This function does not return specific errors, if it fails give a generic message.
      match rustls_pemfile::certs(reader) {
        Ok(certs) => {
          root_cert_store.add_parsable_certificates(
            certs.into_iter().map(CertificateDer::from),
          );
        }
        Err(e) => {
          return Err(anyhow!(
            "Unable to add pem file to certificate store: {}",
            e
          ));
        }
      }
    }
    root_cert_store
  });

  let mut client =
    if let Some((cert_chain, private_key)) = maybe_cert_chain_and_key {
      client_config
        .with_client_auth_cert(cert_chain, private_key)
        .expect("invalid client key or certificate")
    } else {
      client_config.with_no_client_auth()
    };

  add_alpn(&mut client, socket_use);
  Ok(client)
}

fn add_alpn(client: &mut ClientConfig, socket_use: SocketUse) {
  match socket_use {
    SocketUse::Http1Only => {
      client.alpn_protocols = vec!["http/1.1".into()];
    }
    SocketUse::Http2Only => {
      client.alpn_protocols = vec!["h2".into()];
    }
    SocketUse::Http => {
      client.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
    }
    SocketUse::GeneralSsl => {}
  };
}

pub fn load_certs(
  reader: &mut dyn BufRead,
) -> Result<Vec<CertificateDer<'static>>, AnyError> {
  let certs = certs(reader)
    .map_err(|_| custom_error("InvalidData", "Unable to decode certificate"))?;

  if certs.is_empty() {
    let e = custom_error("InvalidData", "No certificates found in cert file");
    return Err(e);
  }

  Ok(certs.into_iter().map(|c| CertificateDer::from(c)).collect())
}

fn key_decode_err() -> AnyError {
  custom_error("InvalidData", "Unable to decode key")
}

fn key_not_found_err() -> AnyError {
  custom_error("InvalidData", "No keys found in key file")
}

/// Starts with -----BEGIN RSA PRIVATE KEY-----
fn load_rsa_keys(
  mut bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, AnyError> {
  let keys = rsa_private_keys(&mut bytes).map_err(|_| key_decode_err())?;
  Ok(
    keys
      .into_iter()
      .map(|pk| PrivatePkcs1KeyDer::from(pk).into())
      .collect(),
  )
}

/// Starts with -----BEGIN PRIVATE KEY-----
fn load_pkcs8_keys(
  mut bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, AnyError> {
  let keys = pkcs8_private_keys(&mut bytes).map_err(|_| key_decode_err())?;
  Ok(
    keys
      .into_iter()
      .map(|pk| PrivatePkcs8KeyDer::from(pk).into())
      .collect(),
  )
}

fn filter_invalid_encoding_err(
  to_be_filtered: Result<HandshakeSignatureValid, Error>,
) -> Result<HandshakeSignatureValid, Error> {
  match to_be_filtered {
    Err(Error::InvalidCertificate(rustls::CertificateError::BadEncoding)) => {
      Ok(HandshakeSignatureValid::assertion())
    }
    res => res,
  }
}

pub fn load_private_keys(
  bytes: &[u8],
) -> Result<Vec<PrivateKeyDer<'static>>, AnyError> {
  let mut keys = load_rsa_keys(bytes)?;

  if keys.is_empty() {
    keys = load_pkcs8_keys(bytes)?;
  }

  if keys.is_empty() {
    return Err(key_not_found_err());
  }

  Ok(keys)
}
