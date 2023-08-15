//! This module contains all resources required for Nifi authentication.
//!
//! Nifi does not support authentication of multiple users with a single login provider, it only has `SingleUserLoginIdentityProvider`,
//! which can authenticate a single user.
//! When implementing the AuthClass `static` provider, we can choose to implement it in the following ways:
//! 1. Introduce new AuthClass `staticSingleUser` similar to `static`, but only with single user allowed in the referenced Secret
//! 2. Use `static`, assert on startup that Secret only contains a single user, use that username and password
//! - static AuthClass can not be re-used between products consuming multiple users and consuming single users
//! 3. Use `static`, assert on startup that Secret only contains "admin" user, use username "admin" and the provided password.
//! Other users are ignored - at least for now, in the future we could write a `SingleUserLoginIdentityProvider` for every individual user
//! if this feature is really needed.
//! + static AuthClass can be re-used between products consuming multiple users and consuming single users
//! + easy to implement and extend the functionality without a breaking change later on
//!
//! Additionally, we always add an SingleUserLoginIdentityProvider for the `create-reporting-task` Job.
pub(crate) mod ldap;
pub(crate) mod reporting_task_user;
pub(crate) mod single_user;

use indoc::indoc;
use serde_json::to_string;
use snafu::{ResultExt, Snafu};
use stackable_nifi_crd::{NifiCluster, NifiRole};
use stackable_operator::k8s_openapi::api::core::v1::EnvVar;
use stackable_operator::{
    builder::{ContainerBuilder, PodBuilder},
    commons::{
        authentication::{
            static_::UserCredentialsSecretRef, AuthenticationClass, AuthenticationClassProvider,
            StaticAuthenticationProvider,
        },
        product_image_selection::ResolvedProductImage,
    },
    k8s_openapi::api::core::v1::{Container, Volume, VolumeMount},
    kube::{runtime::reflector::ObjectRef, ResourceExt},
    product_config,
};
use std::collections::{BTreeMap, HashMap};
use tracing::trace;

use self::{ldap::NifiLdapAuthenticator, single_user::NifiSingleUserAuthenticator};

const LOGIN_IDENTITY_PROVIDERS_XML_FILE_NAME: &str = "login-identity-providers.xml";
const LOGIN_IDENTITY_PROVIDER_XML_START: &str = indoc! {r#"
            <?xml version="1.0" encoding="UTF-8" standalone="no"?>
            <loginIdentityProviders>
        "#};
const LOGIN_IDENTITY_PROVIDER_XML_END: &str = indoc! {r#"
            </loginIdentityProviders>
        "#};

const AUTHORIZERS_XML_FILE_NAME: &str = "authorizers.xml";
const AUTHORIZERS_XML_START: &str = indoc! {r#"
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <authorizers>
        "#};
const AUTHORIZERS_XML_END: &str = indoc! {r#"
            </authorizers>
        "#};

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("The nifi-operator does not support running Nifi without any authentication. Please provide a AuthenticationClass to use."))]
    NoAuthenticationNotSupported {},
    #[snafu(display("The nifi-operator does not support multiple AuthenticationClasses simultaneously. Please provide a single AuthenticationClass to use."))]
    MultipleAuthenticationClassesNotSupported {},
    #[snafu(display("The nifi-operator does not support the AuthenticationClass provider [{authentication_class_provider}] from AuthenticationClass [{authentication_class}]."))]
    AuthenticationClassProviderNotSupported {
        authentication_class_provider: String,
        authentication_class: ObjectRef<AuthenticationClass>,
    },
    // #[snafu(display("Failed to format nifi authentication java properties"))]
    // FailedToWriteJavaProperties {
    //     source: product_config::writer::PropertiesWriterError,
    // },
    // #[snafu(display("Failed to configure Nifi SingleUser authentication"))]
    // InvalidSingleUserAuthenticationConfig { source: single_user::Error },
    #[snafu(display("Failed to configure Nifi LDAP authentication"))]
    InvalidLdapAuthenticationConfig { source: ldap::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// This is the final product after iterating through all authenticators.
/// Contains all relevant information about config files, extra container args etc. to enable authentication.
#[derive(Clone, Debug, Default)]
pub struct NifiAuthenticationConfig {
    /// All config properties that have to be added to the given role
    config_properties: HashMap<NifiRole, BTreeMap<String, String>>,
    /// All extra config files required for authentication for each role.
    config_files: HashMap<NifiRole, BTreeMap<String, String>>,
    /// All extra env variables for the container
    env_vars: Vec<EnvVar>,
    /// All extra container commands for a certain role and container
    commands: HashMap<NifiRole, BTreeMap<stackable_nifi_crd::Container, Vec<String>>>,
    /// Additional volumes like secret mounts, user file database etc.
    volumes: Vec<Volume>,
    /// Additional volume mounts for each role and container. Shared volumes have to be added
    /// manually in each container.
    volume_mounts: HashMap<NifiRole, BTreeMap<stackable_nifi_crd::Container, Vec<VolumeMount>>>,
}

impl NifiAuthenticationConfig {
    pub fn new(auth_type: NifiAuthenticationType) -> Result<Self, Error> {
        let authentication_config = match auth_type {
            NifiAuthenticationType::SingleUser(single_user) => single_user.authentication_config(),
            NifiAuthenticationType::Ldap(ldap) => ldap
                .authentication_config()
                .context(InvalidLdapAuthenticationConfigSnafu)?,
        };

        trace!("Final Nifi authentication config: {authentication_config:?}",);

        Ok(authentication_config)
    }

    /// Automatically add volumes, volume mounts, commands and containers to
    /// the respective pod / container builders.
    pub fn add_authentication_pod_and_volume_config(
        &self,
        role: &NifiRole,
        pod_builder: &mut PodBuilder,
        prepare_builder: &mut ContainerBuilder,
        nifi_builder: &mut ContainerBuilder,
    ) {
        // // volumes
        // pod_builder.add_volumes(self.volumes());
        //
        // let affected_containers = vec![
        //     stackable_nifi_crd::Container::Prepare,
        //     stackable_nifi_crd::Container::Nifi,
        // ];
        //
        // for container in &affected_containers {
        //     //let volume_mounts = self.volume_mounts(&role, container);
        //
        //     match container {
        //         stackable_nifi_crd::Container::Prepare => {
        //             prepare_builder.add_volume_mounts(volume_mounts);
        //         }
        //         stackable_nifi_crd::Container::Nifi => {
        //             nifi_builder.add_volume_mounts(volume_mounts);
        //         }
        //         // nothing to do here
        //         stackable_nifi_crd::Container::Vector => {}
        //     }
        // }
        //
        // // containers
        // for container in self.sidecar_containers(&role) {
        //     pod_builder.add_container(container);
        // }
    }

    pub fn add_config_property(
        &mut self,
        role: NifiRole,
        property_name: String,
        property_value: String,
    ) {
        self.config_properties
            .entry(role)
            .or_insert(BTreeMap::new())
            .insert(property_name, property_value);
    }

    /// Add config file for a given role. The file_content must already be formatted to its final
    /// representation in the file.
    pub fn add_config_file(&mut self, role: NifiRole, file_name: String, file_content: String) {
        self.config_files
            .entry(role)
            .or_insert(BTreeMap::new())
            .insert(file_name, file_content);
    }

    /// Add an EnvVar to the authentication config
    pub fn add_env_var(&mut self, env_var: EnvVar) {
        self.env_vars.push(env_var);
    }

    /// Add additional commands for a given role and container.
    pub fn add_commands(
        &mut self,
        role: NifiRole,
        container: stackable_nifi_crd::Container,
        commands: Vec<String>,
    ) {
        self.commands
            .entry(role)
            .or_insert(BTreeMap::new())
            .entry(container)
            .or_insert(Vec::new())
            .extend(commands)
    }

    /// Add an additional volume for the pod builder.
    pub fn add_volume(&mut self, volume: Volume) {
        if !self.volumes.iter().any(|v| v.name == volume.name) {
            self.volumes.push(volume);
        }
    }

    /// Add an additional volume mount for a role and container.
    /// Volume mounts are only added once and filtered for duplicates.
    pub fn add_volume_mount(
        &mut self,
        role: NifiRole,
        container: stackable_nifi_crd::Container,
        volume_mount: VolumeMount,
    ) {
        let current_volume_mounts = self
            .volume_mounts
            .entry(role)
            .or_insert_with(BTreeMap::new)
            .entry(container)
            .or_insert_with(Vec::new);

        if !current_volume_mounts
            .iter()
            .any(|vm| vm.name == volume_mount.name)
        {
            current_volume_mounts.push(volume_mount);
        }
    }

    /// Retrieve additional properties for the `config.properties` file for a given role.
    pub fn config_properties(&self, role: &NifiRole) -> BTreeMap<String, String> {
        self.config_properties
            .get(role)
            .cloned()
            .unwrap_or_default()
    }

    /// Retrieve additional config files for a given role.
    pub fn config_files(&self, role: &NifiRole) -> BTreeMap<String, String> {
        self.config_files.get(role).cloned().unwrap_or_default()
    }

    /// Retrieve additional env vars
    // TODO: use nifi role?
    pub fn env_vars(&self) -> Vec<EnvVar> {
        self.env_vars.clone()
    }

    /// Retrieve additional container commands for a given role and container.
    pub fn commands(
        &self,
        role: &NifiRole,
        container: &stackable_nifi_crd::Container,
    ) -> Vec<String> {
        self.commands
            .get(role)
            .cloned()
            .unwrap_or_default()
            .get(container)
            .cloned()
            .unwrap_or_default()
    }

    /// Retrieve all required volumes for the pod builder.
    pub fn volumes(&self) -> Vec<Volume> {
        self.volumes.clone()
    }

    /// Retrieve all required volume mounts for a given role.
    pub fn volume_mounts(
        &self,
        role: &NifiRole,
        container: &stackable_nifi_crd::Container,
    ) -> Vec<VolumeMount> {
        if let Some(volume_mounts) = self.volume_mounts.get(role) {
            volume_mounts.get(container).cloned().unwrap_or_default()
        } else {
            Vec::new()
        }
    }
}

/// Representation of all NiFi authentication types (e.g. SingleUser, LDAP).
#[derive(Clone, Debug, strum::Display)]
pub enum NifiAuthenticationType {
    SingleUser(NifiSingleUserAuthenticator),
    Ldap(NifiLdapAuthenticator),
}

impl NifiAuthenticationType {
    pub fn try_from(auth_classes: Vec<AuthenticationClass>) -> std::result::Result<Self, Error> {
        match auth_classes.len() {
            0 => NoAuthenticationNotSupportedSnafu.fail()?,
            1 => {}
            _ => MultipleAuthenticationClassesNotSupportedSnafu.fail()?,
        }

        // SAFETY: At this point `auth_classes` must have a single element
        let auth_class = auth_classes.first().unwrap();
        let auth_class_name = auth_class.name_any();
        Ok(match &auth_class.spec.provider {
            AuthenticationClassProvider::Static(static_provider) => {
                NifiAuthenticationType::SingleUser(NifiSingleUserAuthenticator::new(
                    &auth_class_name,
                    static_provider,
                ))
            }
            AuthenticationClassProvider::Ldap(ldap_provider) => NifiAuthenticationType::Ldap(
                NifiLdapAuthenticator::new(&auth_class_name, ldap_provider),
            ),
            _ => AuthenticationClassProviderNotSupportedSnafu {
                authentication_class_provider: auth_class.spec.provider.to_string(),
                authentication_class: ObjectRef::<AuthenticationClass>::from_obj(&auth_class),
            }
            .fail()?,
        })
    }
}

fn build_login_identity_provider(content: &str) -> String {
    let mut login_identity_provider_xml = LOGIN_IDENTITY_PROVIDER_XML_START.to_string();
    login_identity_provider_xml.push_str(content);
    login_identity_provider_xml.push_str(LOGIN_IDENTITY_PROVIDER_XML_END);
    login_identity_provider_xml
}

fn build_authorizers(content: &str) -> String {
    let mut authorizers_xml = AUTHORIZERS_XML_START.to_string();
    authorizers_xml.push_str(content);
    authorizers_xml.push_str(AUTHORIZERS_XML_END);
    authorizers_xml
}
