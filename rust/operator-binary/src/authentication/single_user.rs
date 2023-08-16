use crate::authentication::{
    build_authorizers, build_login_identity_provider, AUTHORIZERS_XML_FILE_NAME,
    AUTHORIZERS_XML_START, LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME, LOGIN_IDENTITY_PROVIDER_XML_END,
    LOGIN_IDENTITY_PROVIDER_XML_START,
};

use super::NifiAuthenticationConfig;
use indoc::{formatdoc, indoc};
use stackable_nifi_crd::{Container, NifiRole};
use stackable_operator::k8s_openapi::api::core::v1::{
    EnvVar, EnvVarSource, KeyToPath, SecretKeySelector, SecretVolumeSource,
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

const STACKABLE_ADMIN_USER_PASSWORD_PLACEHOLDER: &str = "xxx_singleuser_password_xxx";
const STACKABLE_ADMIN_USER_NAME: &str = "admin";
const STACKABLE_USER_VOLUME_MOUNT_PATH: &str = "/stackable/users";

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
                        <property name="Password">{STACKABLE_ADMIN_USER_PASSWORD_PLACEHOLDER}</property>
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

        authentication_config.add_volume(Volume {
            name: STACKABLE_ADMIN_USER_NAME.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(self.provider.user_credentials_secret.name.to_string()),
                optional: Some(false),
                items: Some(vec![KeyToPath {
                    key: STACKABLE_ADMIN_USER_NAME.to_string(),
                    path: STACKABLE_ADMIN_USER_NAME.to_string(),
                    ..KeyToPath::default()
                }]),
                ..SecretVolumeSource::default()
            }),
            ..Volume::default()
        });

        authentication_config.add_volume_mount(
            NifiRole::Node,
            Container::Prepare,
            VolumeMountBuilder::new(STACKABLE_ADMIN_USER_NAME, STACKABLE_USER_VOLUME_MOUNT_PATH)
                .build(),
        );

        // required startup commands / args in the prepare container
        authentication_config.add_commands(NifiRole::Node, Container::Prepare, vec![
            format!("echo 'Replacing admin password in {LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME}'"),
            format!("sed -i \"s|{STACKABLE_ADMIN_USER_PASSWORD_PLACEHOLDER}|$(cat {STACKABLE_USER_VOLUME_MOUNT_PATH}/{STACKABLE_ADMIN_USER_NAME} | java -jar /bin/stackable-bcrypt.jar)|g\" /stackable/nifi/conf/{LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME}"),
        ]);

        authentication_config
    }
}
