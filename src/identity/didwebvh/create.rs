use affinidi_tdk_common::secrets_resolver::secrets::{Secret, SecretMaterial};
use anyhow::Result;
use didwebvh_rs::prelude::{CreateDIDConfig, Parameters, create_did};

use super::types::LogEntry;

static PORTABLE_DIDS: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

#[cfg(test)]
tokio::task_local! {
    /// The value [`portable_dids`] returns inside a test's scope, instead of the process-global
    /// one, which is set once per process.
    pub(crate) static TEST_PORTABLE_DIDS: bool;
}

/// Install `did.portable` from `gateway.json`. Called once at startup, before any DID is
/// minted; a second call is a no-op.
pub fn init_portable_dids(portable: bool) {
    let _ = PORTABLE_DIDS.set(portable);
}

/// Whether the gateway mints its did:webvh DIDs portable; `false` before initialisation.
pub(crate) fn portable_dids() -> bool {
    #[cfg(test)]
    if let Ok(portable) = TEST_PORTABLE_DIDS.try_with(|portable| *portable) {
        return portable;
    }
    PORTABLE_DIDS
        .get()
        .copied()
        .unwrap_or(false)
}

/// Parameters of a did:webvh birth entry controlled by `multibase_pubkey`. `portable` is
/// written only when [`portable_dids`] is on, so a non-portable birth entry omits it.
pub(crate) fn birth_parameters(multibase_pubkey: &str) -> Parameters {
    Parameters {
        update_keys: Some(std::sync::Arc::new(vec![didwebvh_rs::Multibase::new(multibase_pubkey.to_string())])),
        portable: portable_dids().then_some(true),
        ..Default::default()
    }
}

pub struct WebVhCreateResult {
    pub final_did: String,
    pub scid: String,
    pub log_entry_json: String,
    pub signed_entry: LogEntry,
    pub multibase_pubkey: String,
}

pub(crate) fn strip_jwk_private_key(jwk: &serde_json::Value) -> serde_json::Value {
    let mut pub_jwk = jwk.clone();
    if let Some(obj) = pub_jwk.as_object_mut() {
        obj.remove("d");
    }
    pub_jwk
}

pub(crate) fn extract_public_jwk(secret: &Secret) -> Result<serde_json::Value> {
    let jwk_value = match &secret.secret_material {
        SecretMaterial::JWK(jwk) => {
            serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?
        }
        _ => return Err(anyhow::anyhow!("Secret is not a JWK")),
    };
    Ok(strip_jwk_private_key(&jwk_value))
}

pub(crate) async fn create_webvh_did(
    ed25519_private_jwk: &serde_json::Value,
    did_document: serde_json::Value,
    base_url: &str,
) -> Result<WebVhCreateResult> {
    let temp_key_id = "did:key:temp#temp".to_string();
    let raw_secret = didwebvh_rs::prelude::Secret::from_str(&temp_key_id, ed25519_private_jwk)
        .map_err(|e| anyhow::anyhow!("Failed to convert Ed25519 key to Secret: {}", e))?;
    let multibase_pubkey = raw_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get multibase public key: {}", e))?;
    let did_key_id = format!("did:key:{0}#{0}", multibase_pubkey);
    let mut auth_secret = didwebvh_rs::prelude::Secret::from_str(&did_key_id, ed25519_private_jwk)
        .map_err(|e| anyhow::anyhow!("Failed to build auth secret: {}", e))?;
    auth_secret.id = did_key_id;

    let parameters = birth_parameters(&multibase_pubkey);

    let normalized_base = format!("{}/", base_url.trim_end_matches('/'));
    let create_result = create_did(
        CreateDIDConfig::builder()
            .address(normalized_base)
            .authorization_key(auth_secret)
            .did_document(did_document)
            .parameters(parameters)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build CreateDIDConfig: {}", e))?,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create DID: {}", e))?;

    let final_did = create_result
        .did()
        .to_string();
    let scid = super::identifier::parse_did_webvh(&final_did)?
        .scid
        .ok_or_else(|| anyhow::anyhow!("created did:webvh is missing SCID: {}", final_did))?;

    let log_entry_json = serde_json::to_string(create_result.log_entry())
        .map_err(|e| anyhow::anyhow!("Failed to serialize log entry: {}", e))?;
    let signed_entry: LogEntry =
        serde_json::from_str(&log_entry_json).map_err(|e| anyhow::anyhow!("Failed to deserialize log entry: {}", e))?;

    Ok(WebVhCreateResult {
        final_did,
        scid,
        log_entry_json,
        signed_entry,
        multibase_pubkey,
    })
}

/// Asserts that the birth entry `raw_birth_entry` of `did` writes `portable: true` exactly when
/// `expected` is set, and that the didwebvh-rs resolver accepts it and reports the same.
#[cfg(test)]
pub(crate) async fn assert_birth_entry_portable(
    did: &str,
    raw_birth_entry: &str,
    expected: bool,
) {
    let entry: serde_json::Value = serde_json::from_str(raw_birth_entry).expect("birth entry must be JSON");
    let written = entry
        .pointer("/parameters/portable")
        .cloned();
    if expected {
        assert_eq!(written, Some(serde_json::Value::Bool(true)), "birth entry must set portable: {entry}");
    } else {
        assert!(
            written.is_none() || written == Some(serde_json::Value::Bool(false)),
            "birth entry must leave portable unset or false: {entry}"
        );
    }

    let mut state = didwebvh_rs::DIDWebVHState::default();
    let (_, metadata) = state
        .resolve_log(did, raw_birth_entry, None)
        .await
        .expect("didwebvh-rs must accept the birth entry");
    assert_eq!(metadata.portable, expected);
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_did() -> WebVhCreateResult {
        let key_pair = super::super::generate_ed25519_keypair().expect("ed25519 keypair must be created");
        let placeholder_did = "did:webvh:{SCID}:example.com:agents:portable";
        let did_document = serde_json::json!({
            "id": placeholder_did,
            "@context": ["https://www.w3.org/ns/did/v1"],
            "verificationMethod": [{
                "id": format!("{}#key-1", placeholder_did),
                "type": "JsonWebKey2020",
                "controller": placeholder_did,
                "publicKeyJwk": strip_jwk_private_key(&key_pair.public_key)
            }],
            "authentication": [format!("{}#key-1", placeholder_did)]
        });
        create_webvh_did(&key_pair.private_key, did_document, "https://example.com/")
            .await
            .expect("did:webvh creation must succeed")
    }

    #[tokio::test]
    async fn create_webvh_did_is_portable_when_setting_on() {
        let created = TEST_PORTABLE_DIDS
            .scope(true, create_test_did())
            .await;
        assert_birth_entry_portable(&created.final_did, &created.log_entry_json, true).await;
        assert!(created.signed_entry.parameters.portable);
    }

    #[tokio::test]
    async fn create_webvh_did_is_not_portable_when_setting_off() {
        let created = TEST_PORTABLE_DIDS
            .scope(false, create_test_did())
            .await;
        assert_birth_entry_portable(&created.final_did, &created.log_entry_json, false).await;
    }

    #[tokio::test]
    async fn create_webvh_did_is_not_portable_when_setting_unset() {
        let created = create_test_did().await;
        assert_birth_entry_portable(&created.final_did, &created.log_entry_json, false).await;
    }

    #[test]
    fn birth_parameters_set_portable_only_when_setting_on() {
        let on = TEST_PORTABLE_DIDS.sync_scope(true, || birth_parameters("z6MkTest"));
        let off = TEST_PORTABLE_DIDS.sync_scope(false, || birth_parameters("z6MkTest"));
        assert_eq!(on.portable, Some(true));
        assert_eq!(off.portable, None);
    }

    #[test]
    fn strip_jwk_private_key_removes_d() {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "test_public_value",
            "d": "test_private_value"
        });
        let public = strip_jwk_private_key(&jwk);
        assert!(public.get("d").is_none());
        assert_eq!(
            public
                .get("kty")
                .unwrap()
                .as_str()
                .unwrap(),
            "OKP"
        );
        assert_eq!(
            public
                .get("crv")
                .unwrap()
                .as_str()
                .unwrap(),
            "Ed25519"
        );
        assert_eq!(
            public
                .get("x")
                .unwrap()
                .as_str()
                .unwrap(),
            "test_public_value"
        );
    }

    #[test]
    fn strip_jwk_private_key_noop_when_no_d() {
        let jwk = serde_json::json!({"kty": "OKP", "crv": "Ed25519", "x": "val"});
        let public = strip_jwk_private_key(&jwk);
        assert_eq!(public, jwk);
    }

    #[test]
    fn create_result_scid_parser_requires_scid_segment() {
        let result = super::super::identifier::parse_did_webvh("did:webvh:example.com:agents:alpha")
            .expect("legacy did should still parse");

        assert!(result.scid.is_none());
    }
}
