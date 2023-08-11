use stackable_operator::{
    builder::{
        resources::ResourceRequirementsBuilder, ContainerBuilder, VolumeBuilder, VolumeMountBuilder,
    },
    commons::authentication::StaticAuthenticationProvider,
    commons::product_image_selection::ResolvedProductImage,
    k8s_openapi::api::core::v1::{Container, Volume, VolumeMount},
    product_logging::{self, spec::AutomaticContainerLogConfig},
};
use std::collections::BTreeMap;

use super::NifiAuthenticationConfig;

#[derive(Clone, Debug)]
pub struct NifiSingleUserAuthenticator {
    name: String,
    static_: StaticAuthenticationProvider,
}

impl NifiSingleUserAuthenticator {
    pub fn new(name: &str, provider: &StaticAuthenticationProvider) -> Self {
        Self {
            name: name.to_string(),
            static_: provider.clone(),
        }
    }

    pub fn authentication_config(
        &self,
        resolved_product_image: &ResolvedProductImage,
    ) -> NifiAuthenticationConfig {
        todo!()
    }
}
