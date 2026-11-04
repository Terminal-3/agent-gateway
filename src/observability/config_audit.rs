use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::policies::FileSystemPolicyDefinitionStore;
use crate::surfaces::FileSystemAgentSurfaceStore;
use crate::surfaces::store::AgentSurfaceStore as _;
use crate::trust_registries::FileSystemTrustRegistryStore;
use crate::trust_registries::store::TrustRegistryStore as _;

const INTERVAL: Duration = Duration::from_secs(30);

pub struct ConfigStores {
    pub surfaces: Option<Arc<FileSystemAgentSurfaceStore>>,
    pub policies: Option<Arc<FileSystemPolicyDefinitionStore>>,
    pub trust_registries: Option<Arc<FileSystemTrustRegistryStore>>,
}

pub fn spawn(stores: ConfigStores) {
    tokio::spawn(async move {
        let mut sent: HashMap<(&'static str, String), String> = HashMap::new();
        loop {
            if let Some(objects) = collect(&stores).await {
                for (key, hash) in changes(&mut sent, &objects) {
                    crate::delegation_vault::audit::audit_config_object(
                        key.0,
                        &key.1,
                        hash.and_then(|_| objects.get(&key).cloned()),
                    );
                }
            }
            tokio::time::sleep(INTERVAL).await;
        }
    });
}

async fn collect(stores: &ConfigStores) -> Option<HashMap<(&'static str, String), Value>> {
    let mut objects = HashMap::new();
    if let Some(store) = &stores.surfaces {
        for surface in store.list_all().await.ok()? {
            objects.insert(("surface", surface.surface_id.clone()), serde_json::to_value(&surface).ok()?);
        }
    }
    if let Some(store) = &stores.policies {
        for policy in store.list().await {
            let object = json!({
                "name": policy.name,
                "description": policy.description,
                "policy_type": policy.policy_type,
                "enabled": policy.enabled,
                "version": policy.version,
                "content_hash": policy.content_hash,
                "policy": policy.policy,
            });
            objects.insert(("policy", policy.id), object);
        }
    }
    if let Some(store) = &stores.trust_registries {
        for registry in store.list_all().await.ok()? {
            let full = serde_json::to_value(&registry).ok()?;
            let object: serde_json::Map<String, Value> =
                ["name", "description", "did", "registry_did", "status", "connection_status"]
                    .iter()
                    .filter_map(|k| {
                        full.get(*k)
                            .map(|v| ((*k).to_string(), v.clone()))
                    })
                    .collect();
            objects.insert(("trust_registry", registry.id), Value::Object(object));
        }
    }
    Some(objects)
}

fn changes(
    sent: &mut HashMap<(&'static str, String), String>,
    objects: &HashMap<(&'static str, String), Value>,
) -> Vec<((&'static str, String), Option<String>)> {
    let mut out = Vec::new();
    for (key, object) in objects {
        let hash = hex::encode(Sha256::digest(object.to_string().as_bytes()));
        if sent.get(key) != Some(&hash) {
            sent.insert(key.clone(), hash.clone());
            out.push((key.clone(), Some(hash)));
        }
    }
    let gone: Vec<_> = sent
        .keys()
        .filter(|key| !objects.contains_key(*key))
        .cloned()
        .collect();
    for key in gone {
        sent.remove(&key);
        out.push((key, None));
    }
    out
}
