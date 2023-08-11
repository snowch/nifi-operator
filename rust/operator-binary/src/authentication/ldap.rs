use snafu::Snafu;
use stackable_operator::{
    builder::VolumeMountBuilder,
    commons::{
        authentication::{
            ldap::SECRET_BASE_PATH,
            tls::{CaCert, Tls, TlsServerVerification, TlsVerification},
            LdapAuthenticationProvider,
        },
        product_image_selection::ResolvedProductImage,
        secret_class::SecretClassVolume,
    },
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
};
use std::collections::BTreeMap;

use super::NifiAuthenticationConfig;

// ldap
// const PASSWORD_AUTHENTICATOR_NAME_LDAP: &str = "ldap";
// const LDAP_URL: &str = "ldap.url";
// const LDAP_BIND_DN: &str = "ldap.bind-dn";
// const LDAP_BIND_PASSWORD: &str = "ldap.bind-password";
// const LDAP_USER_BASE_DN: &str = "ldap.user-base-dn";
// const LDAP_GROUP_AUTH_PATTERN: &str = "ldap.group-auth-pattern";
// const LDAP_ALLOW_INSECURE: &str = "ldap.allow-insecure";
// const LDAP_SSL_TRUST_STORE_PATH: &str = "ldap.ssl.truststore.path";
// const LDAP_USER_ENV: &str = "LDAP_USER";
// const LDAP_PASSWORD_ENV: &str = "LDAP_PASSWORD";

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Nifi does not support unverified TLS connections to LDAP"))]
    UnverifiedLdapTlsConnectionNotSupported,
}

#[derive(Clone, Debug)]
pub struct NifiLdapAuthenticator {
    name: String,
    ldap: LdapAuthenticationProvider,
}

impl NifiLdapAuthenticator {
    pub fn new(name: &str, provider: &LdapAuthenticationProvider) -> Self {
        Self {
            name: name.to_string(),
            ldap: provider.clone(),
        }
    }

    pub fn authentication_config(
        &self,
        resolved_product_image: &ResolvedProductImage,
    ) -> Result<NifiAuthenticationConfig, Error> {
        todo!()
    }
}
