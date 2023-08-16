use crate::authentication::{
    build_authorizers, build_login_identity_provider, AUTHORIZERS_XML_FILE_NAME,
    LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME,
};

use indoc::{formatdoc, indoc};
use snafu::Snafu;
use stackable_nifi_crd::NifiRole;
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

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("Nifi does not support unverified TLS connections to LDAP"))]
    UnverifiedLdapTlsConnectionNotSupported,
}

#[derive(Clone, Debug)]
pub struct NifiLdapAuthenticator {
    name: String,
    provider: LdapAuthenticationProvider,
}

impl NifiLdapAuthenticator {
    pub fn new(name: &str, provider: &LdapAuthenticationProvider) -> Self {
        Self {
            name: name.to_string(),
            provider: provider.clone(),
        }
    }

    pub fn authentication_config(&self) -> NifiAuthenticationConfig {
        let mut authentication_config = NifiAuthenticationConfig::default();
        // required config files
        authentication_config.add_config_file(
            NifiRole::Node,
            LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME.to_string(),
            build_login_identity_provider(&self.build_ldap_login_identity_provider()),
        );

        authentication_config.add_config_file(
            NifiRole::Node,
            AUTHORIZERS_XML_FILE_NAME.to_string(),
            build_authorizers(&Self::ldap_authorizer()),
        );

        authentication_config
    }

    fn build_ldap_login_identity_provider(&self) -> String {
        let mut search_filter = self.provider.search_filter.clone();

        // If no search_filter is specified we will set a default filter that just searches for the user logging in using the specified uid field name
        if search_filter.is_empty() {
            search_filter.push_str(
                format!(
                    "{uidField}={{0}}",
                    uidField = self.provider.ldap_field_names.uid
                )
                .as_str(),
            );
        }

        formatdoc! {r#"
        <provider>
            <identifier>login-identity-provider</identifier>
            <class>org.apache.nifi.ldap.LdapProvider</class>
            <property name="Authentication Strategy">{authentication_strategy}</property>

            <property name="Manager DN">xxx_ldap_bind_username_xxx</property>
            <property name="Manager Password">xxx_ldap_bind_password_xxx</property>

            <property name="Referral Strategy">THROW</property>
            <property name="Connect Timeout">10 secs</property>
            <property name="Read Timeout">10 secs</property>

            <property name="Url">{protocol}://{hostname}:{port}</property>
            <property name="User Search Base">{search_base}</property>
            <property name="User Search Filter">{search_filter}</property>

            <property name="TLS - Client Auth">NONE</property>
            <property name="TLS - Keystore">/stackable/keystore/keystore.p12</property>
            <property name="TLS - Keystore Password">secret</property>
            <property name="TLS - Keystore Type">PKCS12</property>
            <property name="TLS - Truststore">/stackable/keystore/truststore.p12</property>
            <property name="TLS - Truststore Password">secret</property>
            <property name="TLS - Truststore Type">PKCS12</property>
            <property name="TLS - Protocol">TLSv1.2</property>
            <property name="TLS - Shutdown Gracefully">true</property>

            <property name="Identity Strategy">USE_DN</property>
            <property name="Authentication Expiration">7 days</property>
        </provider>
    "#,
            authentication_strategy = if self.provider.bind_credentials.is_some() {
                if self.provider.tls.is_some() {
                    "LDAPS"
                } else {
                    "SIMPLE"
                }
            } else {
                "ANONYMOUS"
            },
            protocol = if self.provider.tls.is_some() {
                "ldaps"
            } else {
                "ldap"
            },
            hostname = self.provider.hostname,
            port = self.provider.port.unwrap_or_else(|| self.provider.default_port()),
            search_base = self.provider.search_base,
        }
    }

    fn ldap_authorizer() -> String {
        formatdoc! {r#"
        <userGroupProvider>
            <identifier>file-user-group-provider</identifier>
            <class>org.apache.nifi.authorization.FileUserGroupProvider</class>
            <property name="Users File">./conf/users.xml</property>

            <!-- As we currently don't have authorization (including admin user) configurable we simply paste in the ldap bind user in here -->
            <!-- In the future the whole authorization may be reworked to OPA -->
            <property name="Initial User Identity admin">xxx_ldap_bind_username_xxx</property>

            <!-- As the secret-operator provides the NiFi nodes with cert with a common name of "generated certificate for pod" we have to put that here -->
            <property name="Initial User Identity other-nifis">CN=generated certificate for pod</property>
        </userGroupProvider>

        <accessPolicyProvider>
            <identifier>file-access-policy-provider</identifier>
            <class>org.apache.nifi.authorization.FileAccessPolicyProvider</class>
            <property name="User Group Provider">file-user-group-provider</property>
            <property name="Authorizations File">./conf/authorizations.xml</property>

            <!-- As we currently don't have authorization (including admin user) configurable we simply paste in the ldap bind user in here -->
            <!-- In the future the whole authorization may be reworked to OPA -->
            <property name="Initial Admin Identity">xxx_ldap_bind_username_xxx</property>

            <!-- As the secret-operator provides the NiFi nodes with cert with a common name of "generated certificate for pod" we have to put that here -->
            <property name="Node Identity other-nifis">CN=generated certificate for pod</property>
        </accessPolicyProvider>

        <authorizer>
            <identifier>authorizer</identifier>
            <class>org.apache.nifi.authorization.StandardManagedAuthorizer</class>
            <property name="Access Policy Provider">file-access-policy-provider</property>
        </authorizer>
    "#}
    }
}
