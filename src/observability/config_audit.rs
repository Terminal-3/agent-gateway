use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::policies::FileSystemPolicyDefinitionStore;
use crate::policies::policy_definitions::PolicyDocument;
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
        // A pass after `sent` was emptied sends everything, so it ends with a
        // `full_config` per kind: an object removed meanwhile has no other record.
        let mut full_pass = true;
        loop {
            // A record made while no sink takes it, or before the journal runs
            // (Standby, startup), is dropped: send the whole snapshot again
            // once it can be kept.
            let ready = crate::audit::producer::producer().is_connected()
                && crate::delegation_vault::audit::wants("config_object");
            if !ready {
                sent.clear();
                full_pass = true;
            } else if let Some(objects) = collect(&stores).await {
                for (key, hash) in changes(&mut sent, &objects) {
                    crate::delegation_vault::audit::audit_config_object(
                        key.0,
                        &key.1,
                        hash.and_then(|_| objects.get(&key).cloned()),
                    );
                }
                if full_pass {
                    for (kind, ids) in full_config(&stores.kinds(), &objects) {
                        crate::delegation_vault::audit::audit_full_config(kind, ids);
                    }
                    full_pass = false;
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
        for document in store
            .try_list_documents()
            .await?
        {
            objects.insert(("policy", document.id.clone()), policy_object(&document));
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

impl ConfigStores {
    fn kinds(&self) -> Vec<&'static str> {
        [
            ("surface", self.surfaces.is_some()),
            ("policy", self.policies.is_some()),
            (
                "trust_registry",
                self.trust_registries
                    .is_some(),
            ),
        ]
        .into_iter()
        .filter_map(|(kind, configured)| configured.then_some(kind))
        .collect()
    }
}

/// Every id of each of `kinds`, sorted; a kind with no objects answers an
/// empty list.
fn full_config(
    kinds: &[&'static str],
    objects: &HashMap<(&'static str, String), Value>,
) -> Vec<(&'static str, Vec<String>)> {
    kinds
        .iter()
        .map(|kind| {
            let mut ids: Vec<String> = objects
                .keys()
                .filter(|key| key.0 == *kind)
                .map(|key| key.1.clone())
                .collect();
            ids.sort();
            (*kind, ids)
        })
        .collect()
}

/// The audited view of a policy: its current version, when it was created and
/// last changed and by whom, and the current version's author and time.
/// Absent times and authors are left out. A save that changes nothing leaves
/// the object, and so the audit, unchanged.
fn policy_object(document: &PolicyDocument) -> Value {
    let policy = document.to_definition();
    let current = document.current();
    let mut object = json!({
        "name": policy.name,
        "description": policy.description,
        "policy_type": policy.policy_type,
        "enabled": policy.enabled,
        "version": policy.version,
        "content_hash": policy.content_hash,
        "policy": policy.policy,
        "created_at": policy.created_at,
    });
    let optional = [
        ("updated_at", document.updated_at.clone()),
        ("updated_by", document.updated_by.clone()),
        ("version_created_by", current.and_then(|v| v.created_by.clone())),
        ("version_created_at", current.map(|v| v.created_at.clone())),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            object[key] = Value::String(value);
        }
    }
    object
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};
    use crate::storage::filesystem::StorableEntity as _;

    #[test]
    fn a_full_config_lists_every_id_of_each_kind_and_an_empty_kind_too() {
        let objects = HashMap::from([
            (("policy", "b".to_string()), json!({})),
            (("policy", "a".to_string()), json!({})),
            (("surface", "s".to_string()), json!({})),
        ]);
        assert_eq!(
            full_config(&["policy", "trust_registry"], &objects),
            [("policy", vec!["a".to_string(), "b".to_string()]), ("trust_registry", vec![])]
        );
    }

    fn definition(rego: &str) -> PolicyDefinition {
        PolicyDefinition {
            id: "p1".into(),
            tenant_id: None,
            name: "Deny unknown".into(),
            description: String::new(),
            policy_type: PolicyType::Gateway,
            policy: rego.into(),
            enabled: true,
            created_at: String::new(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        }
    }

    fn renamed(
        definition: PolicyDefinition,
        name: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            name: name.into(),
            ..definition
        }
    }

    #[tokio::test]
    async fn policy_object_names_the_last_change_and_the_current_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp
            .path()
            .to_string_lossy()
            .into_owned();
        let store = FileSystemPolicyDefinitionStore::new(root)
            .await
            .expect("store");
        let v1 = definition("package gateway.policy\ndefault allow = true");
        let v2 = definition("package gateway.policy\ndefault allow = false");
        store
            .save_authored(v1, Some("alice".into()), None)
            .await
            .expect("v1");
        store
            .save_authored(v2.clone(), Some("bob".into()), None)
            .await
            .expect("v2");
        let before = store
            .try_list_documents()
            .await
            .expect("list");
        let before = policy_object(&before[0]);
        assert_eq!(before["version"], 2);
        assert_eq!(before["version_created_by"], "bob");
        assert_eq!(before["updated_by"], "bob");

        // A rename is a change by carol that keeps bob's version.
        let rename = renamed(v2, "Deny all");
        store
            .save_authored(rename.clone(), Some("carol".into()), None)
            .await
            .expect("rename");
        let documents = store
            .try_list_documents()
            .await
            .expect("list");
        let document = &documents[0];
        let current = document
            .current()
            .expect("current");
        let object = policy_object(document);
        assert_eq!(object["name"], "Deny all");
        assert_eq!(object["version"], 2);
        assert_eq!(object["version_created_by"], "bob");
        assert_eq!(object["version_created_at"], before["version_created_at"]);
        assert_eq!(object["version_created_at"], current.created_at.as_str());
        assert_eq!(object["created_at"], document.created_at.as_str());
        assert_eq!(object["updated_by"], "carol");
        assert_ne!(object["updated_at"], before["updated_at"]);
        assert_eq!(
            object["updated_at"],
            document
                .updated_at
                .as_deref()
                .expect("updated_at")
        );

        // A save that changes nothing leaves the object as it was.
        store
            .save_authored(rename, Some("dave".into()), None)
            .await
            .expect("no-op");
        let documents = store
            .try_list_documents()
            .await
            .expect("list");
        assert_eq!(policy_object(&documents[0]), object);
    }

    #[tokio::test]
    async fn policy_object_names_who_changed_the_owner() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp
            .path()
            .to_string_lossy()
            .into_owned();
        let store = FileSystemPolicyDefinitionStore::new(root)
            .await
            .expect("store");
        store
            .save_authored(definition("package gateway.policy"), Some("alice".into()), None)
            .await
            .expect("v1");
        store
            .set_tenant_id("p1", Some("tenant-a".into()), Some("erin".into()))
            .await
            .expect("owner");
        let documents = store
            .try_list_documents()
            .await
            .expect("list");
        let object = policy_object(&documents[0]);
        assert_eq!(object["updated_by"], "erin");
        assert_eq!(object["version_created_by"], "alice");
    }

    #[test]
    fn policy_object_omits_the_author_of_a_legacy_policy() {
        let mut value = json!({
            "id": "legacy",
            "name": "Legacy",
            "policy_type": "gateway",
            "policy": "package gateway.policy\ndefault allow = true",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        PolicyDocument::migrate_raw_json(&mut value).expect("migrate");
        let document: PolicyDocument = serde_json::from_value(value).expect("document");

        let object = policy_object(&document);
        assert!(
            object
                .get("version_created_by")
                .is_none()
        );
        assert!(
            object
                .get("updated_by")
                .is_none()
        );
        assert_eq!(object["version_created_at"], "2026-01-01T00:00:00Z");
        assert_eq!(object["created_at"], "2026-01-01T00:00:00Z");
    }
}
