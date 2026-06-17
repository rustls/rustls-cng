use std::{fmt, hash::Hasher, sync::Arc};

use rustls::{
    ClientConfig, ConfigBuilder, Error, ServerConfig,
    client::{ClientCredentialResolver, CredentialRequest, WantsClientCert},
    crypto::{Credentials, Identity, SelectedCredential},
    enums::CertificateType,
    pki_types::CertificateDer,
    server::{ClientHello, ServerCredentialResolver, WantsServerCert},
};

use crate::{key::NCryptKey, signer::CngSigningKey};

/// CNG credentials with a private key and a certificate chain.
#[derive(Debug)]
pub struct CngCredentials {
    key: NCryptKey,
    chain: Vec<CertificateDer<'static>>,
}

impl CngCredentials {
    /// Create credentials from a private key and certificate chain.
    pub fn new(key: NCryptKey, chain: Vec<CertificateDer<'static>>) -> Self {
        Self { key, chain }
    }

    /// Get the private key.
    pub fn key(&self) -> &NCryptKey {
        &self.key
    }

    /// Get the certificate chain.
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }
}

/// Extension trait for `ConfigBuilder` to add CNG client credentials.
pub trait WithCngClientCredentials {
    /// Add CNG client credentials.
    fn with_cng_client_credentials(self, credentials: CngCredentials) -> Result<ClientConfig, Error>;
}

impl WithCngClientCredentials for ConfigBuilder<ClientConfig, WantsClientCert> {
    fn with_cng_client_credentials(self, credentials: CngCredentials) -> Result<ClientConfig, Error> {
        let key = CngSigningKey::new(credentials.key).map_err(|_| Error::NoSuitableCertificate)?;
        let identity = Identity::from_cert_chain(credentials.chain)?;
        self.with_client_credential_resolver(Arc::new(ClientCertResolver {
            key,
            identity: Arc::new(identity),
        }))
    }
}

#[derive(Debug)]
struct ClientCertResolver {
    key: CngSigningKey,
    identity: Arc<Identity<'static>>,
}

impl ClientCredentialResolver for ClientCertResolver {
    fn resolve(&self, request: &CredentialRequest<'_>) -> Option<SelectedCredential> {
        Credentials::new_unchecked(self.identity.clone(), Box::new(self.key.clone()))
            .signer(request.signature_schemes())
    }

    fn supported_certificate_types(&self) -> &'static [CertificateType] {
        &[CertificateType::X509]
    }

    fn hash_config(&self, _h: &mut dyn Hasher) {}
}

/// Extension trait for ConfigBuilder to add CNG server credentials.
pub trait WithCngServerCredentials {
    /// Register CNG server credentials resolver function.
    fn with_cng_server_credentials<F>(self, resolver: F) -> Result<ServerConfig, Error>
    where
        F: Fn(&ClientHello) -> Result<CngCredentials, Error> + Send + Sync + 'static;
}

impl WithCngServerCredentials for ConfigBuilder<ServerConfig, WantsServerCert> {
    fn with_cng_server_credentials<F>(self, resolver: F) -> Result<ServerConfig, Error>
    where
        F: Fn(&ClientHello) -> Result<CngCredentials, Error> + Send + Sync + 'static,
    {
        self.with_server_credential_resolver(Arc::new(ServerCertResolver(resolver)))
    }
}

struct ServerCertResolver<F>(F);

impl<F> fmt::Debug for ServerCertResolver<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerCertResolver").finish()
    }
}

impl<F> ServerCredentialResolver for ServerCertResolver<F>
where
    F: Fn(&ClientHello) -> Result<CngCredentials, Error> + Send + Sync + 'static,
{
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<SelectedCredential, Error> {
        let credentials = self.0(client_hello)?;

        let signing_key = CngSigningKey::new(credentials.key.clone()).map_err(|_| Error::NoSuitableCertificate)?;

        Credentials::new_unchecked(
            Arc::new(Identity::from_cert_chain(credentials.chain.clone())?),
            Box::new(signing_key),
        )
        .signer(client_hello.signature_schemes())
        .ok_or_else(|| Error::General("No common schemes".to_owned()))
    }
}
