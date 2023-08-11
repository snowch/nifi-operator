//! This module contains all resources required for Nifi authentication.
//!
//! Nifi does not support authentication of multiple users with a single login provider, it only has `SingleUserLoginIdentityProvider`,
//! which can authenticate a single user. However, you can chain multiple LoginIdentityProviders.
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

use snafu::{ResultExt, Snafu};
use stackable_nifi_crd::{NifiCluster, NifiRole};
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
/// Contains all relevant information about config files, volumes etc. to enable authentication.
#[derive(Clone, Debug, Default)]
pub struct NifiAuthenticationConfig {
    /// All config properties that have to be added to the given role
    config_properties: HashMap<NifiRole, BTreeMap<String, String>>,
    /// All extra config files required for authentication for each role.
    config_files: HashMap<NifiRole, BTreeMap<String, String>>,
    /// All extra container commands for a certain role and container
    commands: HashMap<NifiRole, BTreeMap<stackable_nifi_crd::Container, Vec<String>>>,
    /// Additional volumes like secret mounts, user file database etc.
    volumes: Vec<Volume>,
    /// Additional volume mounts for each role and container. Shared volumes have to be added
    /// manually in each container.
    volume_mounts: HashMap<NifiRole, BTreeMap<stackable_nifi_crd::Container, Vec<VolumeMount>>>,
    /// Additional side car container for the provided role
    sidecar_containers: HashMap<NifiRole, Vec<Container>>,
}

impl NifiAuthenticationConfig {
    pub fn new(
        resolved_product_image: &ResolvedProductImage,
        nifi_auth: NifiAuthenticationTypes,
    ) -> Result<Self, Error> {
        let mut authentication_config = NifiAuthenticationConfig::default();

        for auth_type in &nifi_auth.authentication_types {
            match auth_type {
                NifiAuthenticationType::SingleUser(single_user) => authentication_config
                    .extend(single_user.authentication_config(resolved_product_image)),
                NifiAuthenticationType::Ldap(ldap) => authentication_config.extend(
                    ldap.authentication_config(resolved_product_image)
                        .context(InvalidLdapAuthenticationConfigSnafu)?,
                ),
            }
        }

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
        // volumes
        pod_builder.add_volumes(self.volumes());

        let affected_containers = vec![
            stackable_nifi_crd::Container::Prepare,
            stackable_nifi_crd::Container::Nifi,
        ];

        for container in &affected_containers {
            let volume_mounts = self.volume_mounts(&role, container);

            match container {
                stackable_nifi_crd::Container::Prepare => {
                    prepare_builder.add_volume_mounts(volume_mounts);
                }
                stackable_nifi_crd::Container::Nifi => {
                    nifi_builder.add_volume_mounts(volume_mounts);
                }
                // nothing to do here
                stackable_nifi_crd::Container::Vector => {}
            }
        }

        // containers
        for container in self.sidecar_containers(&role) {
            pod_builder.add_container(container);
        }
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

    /// Add an extra sidecar container for a given role
    pub fn add_sidecar_container(&mut self, role: NifiRole, container: Container) {
        let containers_for_role = self.sidecar_containers.entry(role).or_insert_with(Vec::new);

        if !containers_for_role.iter().any(|c| c.name == container.name) {
            containers_for_role.push(container);
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

    /// Retrieve all required sidecar containers for a given role.
    pub fn sidecar_containers(&self, role: &NifiRole) -> Vec<Container> {
        self.sidecar_containers
            .get(role)
            .cloned()
            .unwrap_or_default()
    }

    /// This is a helper to easily extend/merge this struct
    fn extend(&mut self, other: Self) {
        for (role, data) in other.config_properties {
            self.config_properties
                .entry(role)
                .or_insert_with(BTreeMap::new)
                .extend(data)
        }

        for (role, data) in other.config_files {
            self.config_files
                .entry(role)
                .or_insert_with(BTreeMap::new)
                .extend(data)
        }

        self.volumes.extend(other.volumes);

        for (role, containers) in other.commands {
            for (container, commands) in containers {
                self.commands
                    .entry(role.clone())
                    .or_insert_with(BTreeMap::new)
                    .entry(container)
                    .or_insert_with(Vec::new)
                    .extend(commands)
            }
        }

        for (role, containers) in other.volume_mounts {
            for (container, data) in containers {
                self.volume_mounts
                    .entry(role.clone())
                    .or_insert_with(BTreeMap::new)
                    .entry(container)
                    .or_insert_with(Vec::new)
                    .extend(data)
            }
        }

        for (role, data) in other.sidecar_containers {
            self.sidecar_containers
                .entry(role)
                .or_insert_with(Vec::new)
                .extend(data)
        }
    }
}

/// Representation of all NiFi authentication types (e.g. SingleUser, LDAP).
#[derive(Clone, Debug, strum::Display)]
pub enum NifiAuthenticationType {
    #[strum(
        serialize = "org.apache.nifi.authentication.single.user.SingleUserLoginIdentityProvider"
    )]
    SingleUser(NifiSingleUserAuthenticator),
    #[strum(serialize = "org.apache.nifi.ldap.LdapProvider")]
    Ldap(NifiLdapAuthenticator),
}

/// Helper for AuthenticationClass conversion.
#[derive(Clone, Debug, Default)]
pub struct NifiAuthenticationTypes {
    // All authentication classes sorted into the Nifi interpretation
    authentication_types: Vec<NifiAuthenticationType>,
}

impl NifiAuthenticationTypes {
    pub fn try_from(
        nifi: &NifiCluster,
        auth_classes: Vec<AuthenticationClass>,
    ) -> std::result::Result<Self, Error> {
        let mut authentication_types = Vec::new();
        match auth_classes.len() {
            0 => NoAuthenticationNotSupportedSnafu.fail()?,
            1 => {}
            _ => MultipleAuthenticationClassesNotSupportedSnafu.fail()?,
        }

        // We always add a SingleUser authenticator for the reporting task
        authentication_types.push(reporting_task_user::create_authenticator(nifi));

        // SAFETY: At this point `auth_classes` must have a single element
        let auth_class = auth_classes.first().unwrap();
        let auth_class_name = auth_class.name_any();
        authentication_types.push(match &auth_class.spec.provider {
            AuthenticationClassProvider::Ldap(ldap) => {
                NifiAuthenticationType::Ldap(NifiLdapAuthenticator::new(&auth_class_name, ldap))
            }
            AuthenticationClassProvider::Static(static_) => NifiAuthenticationType::SingleUser(
                NifiSingleUserAuthenticator::new(&auth_class_name, static_),
            ),
            _ => AuthenticationClassProviderNotSupportedSnafu {
                authentication_class_provider: auth_class.spec.provider.to_string(),
                authentication_class: ObjectRef::<AuthenticationClass>::from_obj(&auth_class),
            }
            .fail()?,
        });

        Ok(NifiAuthenticationTypes {
            authentication_types,
        })
    }
}
