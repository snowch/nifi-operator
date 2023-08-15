use crate::authentication::{
    build_authorizers, build_login_identity_provider, AUTHORIZERS_XML_FILE_NAME,
    AUTHORIZERS_XML_START, LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME, LOGIN_IDENTITY_PROVIDER_XML_END,
    LOGIN_IDENTITY_PROVIDER_XML_START,
};

use super::NifiAuthenticationConfig;
use indoc::{formatdoc, indoc};
use stackable_nifi_crd::{Container, NifiRole};
use stackable_operator::k8s_openapi::api::core::v1::{
    EnvVar, EnvVarSource, SecretKeySelector, SecretVolumeSource,
};
use stackable_operator::{
    builder::{
        resources::ResourceRequirementsBuilder, ContainerBuilder, VolumeBuilder, VolumeMountBuilder,
    },
    commons::{
        authentication::StaticAuthenticationProvider, product_image_selection::ResolvedProductImage,
    },
    k8s_openapi::api::core::v1::{Volume, VolumeMount},
    product_logging::{self, spec::AutomaticContainerLogConfig},
};
use std::collections::BTreeMap;

const STACKABLE_ADMIN_USER_PASSWORD: &str = "STACKABLE_ADMIN_USER_PASSWORD";
const STACKABLE_ADMIN_USER_NAME: &str = "admin";

#[derive(Clone, Debug)]
pub struct NifiSingleUserAuthenticator {
    name: String,
    provider: StaticAuthenticationProvider,
}

impl NifiSingleUserAuthenticator {
    pub fn new(name: &str, provider: &StaticAuthenticationProvider) -> Self {
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
            // We expect the "admin" user in the provided user secret. If no "admin" key exists
            // in the secret the NiFi pods will fail to start with a container config error.
            // Therefore we can just hardcode "admin" here.
            build_login_identity_provider(&formatdoc! {r#"
                    <provider>
                        <identifier>login-identity-provider</identifier>
                        <class>org.apache.nifi.authentication.single.user.SingleUserLoginIdentityProvider</class>
                        <property name="Username">{STACKABLE_ADMIN_USER_NAME}</property>
                        <property name="Password">xxx_singleuser_password_xxx</property>
                    </provider>
                "#}),
        );

        authentication_config.add_config_file(
            NifiRole::Node,
            AUTHORIZERS_XML_FILE_NAME.to_string(),
            build_authorizers(indoc! {r#"
                    <authorizer>
                        <identifier>authorizer</identifier>
                        <class>org.apache.nifi.authorization.single.user.SingleUserAuthorizer</class>
                    </authorizer>
                "#}),
        );

        authentication_config.add_env_var(EnvVar {
            name: STACKABLE_ADMIN_USER_PASSWORD.to_string(),
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    optional: Some(false),
                    name: Some(self.provider.user_credentials_secret.name.to_string()),
                    key: STACKABLE_ADMIN_USER_NAME.to_string(),
                }),
                ..EnvVarSource::default()
            }),
            ..EnvVar::default()
        });

        // required startup commands / args
        authentication_config.add_commands(NifiRole::Node, Container::Prepare, vec![
            format!("echo 'Replacing admin password in {LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME} (if configured)'"),
            format!("sed -i \"s|xxx_singleuser_password_xxx|$(echo ${STACKABLE_ADMIN_USER_PASSWORD}|  java -jar /bin/stackable-bcrypt.jar)|g\" /stackable/nifi/conf/{LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME}"),
        ]);

        authentication_config
    }
}
