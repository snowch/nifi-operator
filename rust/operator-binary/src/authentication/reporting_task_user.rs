use std::collections::BTreeMap;

use rand::{distributions::Alphanumeric, thread_rng, Rng};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_nifi_crd::NifiCluster;
use stackable_operator::{
    builder::ObjectMetaBuilder,
    client::Client,
    commons::authentication::{static_::UserCredentialsSecretRef, StaticAuthenticationProvider},
    k8s_openapi::api::core::v1::Secret,
    kube::ResourceExt,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::controller::CONTROLLER_NAME;

use super::{single_user::NifiSingleUserAuthenticator, NifiAuthenticationType};

// We have to use admin, as otherwise we can not re-use the `staticAuthClass` mechanism, which requires the user to be called `admin`
const REPORTING_TASK_USERNAME: &str = "admin";

#[derive(Snafu, Debug, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("object defines no namespace"))]
    ObjectHasNoNamespace,
    #[snafu(display("failed to retrieve secret for reporting task user"))]
    FailedToRetrieveReportingTaskUserSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to apply reporting task user secret"))]
    ApplyReportingTaskUserSecret {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("object is missing metadata to build owner reference"))]
    ObjectMissingMetadataForOwnerRef {
        source: stackable_operator::error::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub fn create_authenticator(nifi: &NifiCluster) -> NifiAuthenticationType {
    NifiAuthenticationType::SingleUser(NifiSingleUserAuthenticator {
        name: "create-reporting-task-user".to_string(),
        static_: StaticAuthenticationProvider {
            user_credentials_secret: UserCredentialsSecretRef {
                name: build_secret_name(nifi),
            },
        },
    })
}

pub async fn ensure_credentials_secret(nifi: &NifiCluster, client: &Client) -> Result<()> {
    let secret = build_shared_internal_secret(nifi)?;
    if client
        .get_opt::<Secret>(
            &secret.name_any(),
            secret
                .namespace()
                .as_deref()
                .context(ObjectHasNoNamespaceSnafu)?,
        )
        .await
        .context(FailedToRetrieveReportingTaskUserSecretSnafu)?
        .is_none()
    {
        client
            .apply_patch(CONTROLLER_NAME, &secret, &secret)
            .await
            .context(ApplyReportingTaskUserSecretSnafu)?;
    }

    Ok(())
}

fn build_shared_internal_secret(nifi: &NifiCluster) -> Result<Secret> {
    let mut secret = BTreeMap::new();
    secret.insert(REPORTING_TASK_USERNAME.to_string(), get_random_base64());

    Ok(Secret {
        immutable: Some(true),
        metadata: ObjectMetaBuilder::new()
            .name(build_secret_name(nifi))
            .namespace_opt(nifi.namespace())
            .ownerreference_from_resource(nifi, None, Some(true))
            .context(ObjectMissingMetadataForOwnerRefSnafu)?
            .build(),
        string_data: Some(secret),
        ..Secret::default()
    })
}

fn build_secret_name(nifi: &NifiCluster) -> String {
    format!("{}-reporting-task-user", nifi.name_any())
}

fn get_random_base64() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(40)
        .map(char::from)
        .collect()
}
