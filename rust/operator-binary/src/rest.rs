use reqwest::{Client, Response, Url};
use serde::{Deserialize, Serialize};
use serde_json::json;
use snafu::{ResultExt, Snafu};
use strum_macros::Display;
use strum_macros::EnumIter;

#[derive(Snafu, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("Error when communicationg with NiFi rest endpoint to [{}]", reason))]
    Reqwest {
        source: reqwest::Error,
        reason: String,
    },
    #[snafu(display("Error parsing [{}] as valid baseurl for Nifi Api", url))]
    UnparseableUrl { url: String },
}

pub struct NifiRest {
    base_url: Url,
    user: String,
    password: String,
    client: Client,
}

#[derive(Debug, Display, EnumIter, Serialize, Deserialize)]
pub enum NodeStatus {
    #[strum(serialize = "DISCONNECTING")]
    Disconnecting,
    #[strum(serialize = "OFFLOADING")]
    Offloading,
}

impl NifiRest {
    pub fn new(url: String, user: String, password: String) -> Result<Self, Error> {
        Ok(NifiRest {
            base_url: Url::parse(&url).unwrap(),
            user,
            password,
            client: Default::default(),
        })
    }

    pub async fn get_token(&self) -> Result<String, Error> {
        let token_endpoint = self.base_url.join("/nifi-api/access/token").unwrap();
        let params = [("username", &self.user), ("password", &self.password)];
        let response: Response = self
            .client
            .post(token_endpoint)
            .form(&params)
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=UTF-8",
            )
            .send()
            .await
            .with_context(|| Reqwest {
                reason: "obtain token",
            })?;
        tracing::info!("Got response from NiFi: {:?}", response);
        if response.status().is_success() {
            Ok(response.text().await.with_context(|| Reqwest {
                reason: "obtain token",
            })?)
        } else {
            Ok("".to_string())
        }
    }

    pub async fn disconnect_node(&self, node_id: &str) -> Result<(), Error> {
        Ok(self
            .update_node_status(node_id, NodeStatus::Disconnecting)
            .await?)
    }

    pub async fn offload_node(&self, node_id: &str) -> Result<(), Error> {
        Ok(self
            .update_node_status(node_id, NodeStatus::Offloading)
            .await?)
    }

    async fn get_node_uuid(&self, node_id: &str) -> Result<String, Error> {
        Ok("".to_string())
    }

    async fn update_node_status(&self, node_id: &str, status: NodeStatus) -> Result<(), Error> {
        // Inspired by: https://issues.apache.org/jira/browse/NIFI-3295
        let node_uuid = self.get_node_uuid(node_id).await?;
        let request_body = json!({
        "node": {
            "nodeId": node_uuid,
            "status": status
        }});
        let node_endpoint = self
            .base_url
            .join(&format!("/nifi-api/controller/cluster/nodes/{}", node_id)).unwrap();
        self.client
            .put(node_endpoint)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .await
            .with_context(|| Reqwest {
                reason: "update status",
            })?;
        Ok(())
    }
}
