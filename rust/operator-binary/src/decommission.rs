use crate::StatefulSet;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_nifi_crd::{NifiCluster, NifiRole};
use stackable_operator::client::Client;
use std::collections::BTreeMap;

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("Kubernetes reported error when accessing [{}/{}]", name, namespace))]
    KubeX {
        source: stackable_operator::error::Error,
        name: String,
        namespace: String,
    },
    #[snafu(display("Missing mandatory element from k8s object: [{}]", element))]
    MissingMandatoryElement { element: String },
}

pub fn is_decommissioning(nifi: &NifiCluster) -> bool {
    if let Some(status) = &nifi.status {
        // Found status, check if decommissioning nodes are set
        return match &status.decommissioning_nodes {
            Some(nodes) => !nodes.is_empty(),
            None => false,
        };
    }
    // No Status was set, so we can't be decommissioning
    false
}

pub async fn remove_decommissioned_nodes() -> Result<bool, Error> {
    Ok(false)
}

pub async fn is_shrinking(
    client: &Client,
    nifi: &NifiCluster,
) -> Result<Option<BTreeMap<String, Vec<String>>>, Error> {
    // TODO: This currently doesn't ever return a None, should come up with some .get_or_insert
    //  trickery to implement this
    let mut nodes_to_remove: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (group_name, group_config) in nifi.spec.nodes.clone().unwrap().role_groups {
        let statefulset_name = format!(
            "{}-{}-{}",
            &nifi.metadata.name.clone().unwrap(),
            NifiRole::Node.to_string(),
            &group_name
        );
        let namespace = &nifi
            .metadata
            .namespace
            .clone()
            .unwrap_or("default".to_string());

        let current_ss = client
            .get::<StatefulSet>(&statefulset_name, Some(namespace))
            .await
            .with_context(|| KubeX {
                name: statefulset_name.clone(),
                namespace: namespace.to_string(),
            })?;

        // TODO: Make the below work
        /*
        {
            Ok(statefulset) => statefulset,
            Err(KubeError {
                source: kube::error::Error::Api(ErrorResponse { reason, .. }),
            }) if reason == "NotFound" => continue,
            Err(err) => {
                return Err(KubeX {
                    source: err,
                    name: statefulset_name,
                    namespace: namespace.to_string(),
                })
            }
        };*/

        let current_replicas = current_ss
            .spec
            .with_context(|| MissingMandatoryElement { element: "spec" })?
            .replicas
            .with_context(|| MissingMandatoryElement { element: "name" })?;

        let target_replicas = i32::from(group_config.replicas.unwrap());

        if target_replicas < current_replicas {
            // TODO: replice this with code that retrieves the pods, sorts and picks the ones that
            //  will be removed
            let excess_nodes = (target_replicas..current_replicas)
                .into_iter()
                .map(|pod_number| format!("{}-{}", &statefulset_name, &pod_number))
                .collect::<Vec<String>>();

            tracing::warn!(
                "Target size of [{}] is [{}] pods, statefulset has [{}] replicas -> Shrinking these nodes: [{:?}]",
                group_name,
                target_replicas,
                current_replicas,
                excess_nodes
            );
            nodes_to_remove.insert(group_name, excess_nodes);
        } else {
            tracing::info!(
                "Target size of [{}] is [{}] pods, statefulset has [{}] replicas.",
                group_name,
                target_replicas,
                current_replicas,
            );
        }
    }
    Ok(Some(nodes_to_remove))
}

pub async fn decommission_nodes(nodes: BTreeMap<String, Vec<String>>) -> Result<(), Error> {
    // send disconnect

    // send offload
    Ok(())
}
