//! Detail types for the governance audit events raised on the request path and by
//! management changes to policies.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    Jwt,
    ApiKey,
    DidAuth,
    Mtls,
    McpResourceToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitScope {
    Surface,
    SseSessions,
    FabricCapacity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionStage {
    Routing,
    Admission,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    NoRoute,
    UnknownVariant,
    VariantDisabled,
    /// The surface's `default_variant_id` names no variant.
    MisconfiguredDefault,
    BodyTooLarge,
    ProtocolMismatch,
    InvalidEnvelope,
    InvalidRequestShape,
    VersionUnsupported,
    McpAdmission,
    ExtensionRejected,
    SsrfBlocked,
    ConsentIdentityRequired,
    /// A Fabric request whose `X-Gateway-Fabric-Hops` is not one integer from 1 to 255.
    FabricHopsInvalid,
    /// A Fabric request past the limit of Fabric crossings.
    FabricChainTooLong,
    /// A Fabric request whose managed agent should get a transit token, which
    /// could not be issued.
    TransitTokenUnavailable,
    /// A Fabric request that a per-user delegated credential binding applies
    /// to, on a surface that does not release them to partners.
    DelegationNotEnabledForPartners,
    /// A Fabric request whose per-user delegated credential needs consent,
    /// which is never started through a partner.
    ConsentNotAvailableForPartners,
    /// A closed Access Point without source authentication refused the
    /// request with `503`.
    AccessPointNotReady,
    /// A request to a Target bound by external consent whose path the vendor
    /// might read otherwise than the gateway, or that is not one the grant is
    /// sent to.
    TargetPathRefused,
    /// A request to a Target bound by external consent with a method the
    /// grant is not sent with.
    TargetMethodRefused,
    /// A request to a Target bound by external consent refused before its
    /// grant is read, for a reason a new connect would not fix.
    ConnectorUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBindingFailure {
    /// The request carried no identity binding VP.
    Absent,
    /// The VP failed verification.
    Invalid,
    /// The VP verified, but no trust anchor vouches for its issuer.
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationFailureReason {
    ConsentIdentityMismatch,
    ApiKeyResolutionFailed,
    VaultStoreRejected,
    CoordinatedRefreshUnavailable,
    CredentialsUnavailable,
    AnonymousCaller,
    ContinuationError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestFailureOutcome {
    UpstreamError,
    UpstreamTimeout,
    GatewayFault,
    CircuitOpen,
    ResponseInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Http,
    Fabric,
    McpProxy,
    A2aProxy,
}

/// A policy change, named as its audit event. A refusal names the change that
/// was attempted with one of these.
#[allow(clippy::enum_variant_names, reason = "each variant serializes as its audit event name")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChangeAction {
    PolicyCreated,
    PolicyUpdated,
    PolicyDeleted,
    PolicyAttached,
    PolicyDetached,
    PolicyAttachmentChanged,
}

/// What a policy is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTargetKind {
    Surface,
    Gateway,
    /// The appliance-wide (global) assignments.
    Appliance,
}

/// Where on its target a policy is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySlot {
    /// A surface's target request policy, or a gateway's policy.
    Target,
    /// The Access Point inbound policy.
    Inbound,
    /// The target response policy.
    Response,
    /// The policy shared by every transit point.
    Transit,
    /// One transit point's request or response policy.
    TransitPoint,
    McpTool,
    /// The condition of an MCP tool gate.
    McpToolGate,
    /// An appliance-wide plane.
    Plane,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Enforced,
    MonitorOnly,
}

/// A part of a policy definition a change touched. The record names the part,
/// never its contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyField {
    Rego,
    Name,
    Description,
    Enabled,
    SampleInput,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Pat,
    /// The gateway itself, e.g. pruning a deleted definition's assignments.
    System,
}

/// Who made a management change: its ids, plus the names of the person behind
/// it when known. The ids identify the actor, since names can collide; the
/// record never carries a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Actor {
    pub kind: ActorKind,
    /// The user id, the access token's id, or `gateway`.
    pub id: String,
    /// For an access token, the id of the user it belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The user's username; for an access token, its owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The user's first and last name; for an access token, its owner's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Actor {
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::User,
            id: id.into(),
            user_id: None,
            username: None,
            name: None,
        }
    }

    pub fn pat(
        token_id: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        Self {
            kind: ActorKind::Pat,
            id: token_id.into(),
            user_id: Some(user_id.into()),
            username: None,
            name: None,
        }
    }

    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: "gateway".to_string(),
            user_id: None,
            username: None,
            name: None,
        }
    }

    /// This actor naming the person behind it.
    pub fn with_names(
        mut self,
        username: Option<String>,
        name: Option<String>,
    ) -> Self {
        self.username = username;
        self.name = name;
        self
    }
}

/// A first and last name joined with a space, or `None` when both are empty.
pub fn full_name(
    first_name: Option<&str>,
    last_name: Option<&str>,
) -> Option<String> {
    let name = [first_name, last_name]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (!name.is_empty()).then_some(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyChangeSource {
    /// A management API request changed the policy or where it applies.
    Api,
    /// The tenant owning the policy or gateway was reassigned.
    Ownership,
    /// Deleting a definition removed it from where it applied.
    DefinitionDeleted,
}

/// Why a policy change was refused, by the class of status it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// 403: not permitted, including an appliance limit reached.
    Forbidden,
    /// 404: the policy or target does not exist or is not visible.
    NotFound,
    /// 400 or 422: the change was not valid.
    Invalid,
    /// 409: the change conflicts with what is stored.
    Conflict,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_name_joins_whichever_parts_are_present() {
        assert_eq!(full_name(Some("Ada"), Some("Lovelace")).as_deref(), Some("Ada Lovelace"));
        assert_eq!(full_name(Some(" Ada "), None).as_deref(), Some("Ada"));
        assert_eq!(full_name(Some(""), Some("Lovelace")).as_deref(), Some("Lovelace"));
        assert_eq!(full_name(Some(" "), Some("")), None);
        assert_eq!(full_name(None, None), None);
    }

    #[test]
    fn an_actor_names_the_person_behind_it() {
        let user = Actor::user("u-1").with_names(Some("ada".to_string()), Some("Ada Lovelace".to_string()));
        let pat = Actor::pat("t-1", "u-1").with_names(Some("ada".to_string()), None);

        assert_eq!(
            serde_json::to_value(&user).unwrap(),
            serde_json::json!({"kind": "user", "id": "u-1", "username": "ada", "name": "Ada Lovelace"})
        );
        assert_eq!(
            serde_json::to_value(&pat).unwrap(),
            serde_json::json!({"kind": "pat", "id": "t-1", "user_id": "u-1", "username": "ada"})
        );
    }

    #[test]
    fn an_actor_without_names_leaves_them_out() {
        assert_eq!(serde_json::to_value(Actor::user("u-1")).unwrap(), serde_json::json!({"kind": "user", "id": "u-1"}));
        assert_eq!(
            serde_json::to_value(Actor::system()).unwrap(),
            serde_json::json!({"kind": "system", "id": "gateway"})
        );
        let read: Actor = serde_json::from_value(serde_json::json!({"kind": "user", "id": "u-1"})).unwrap();
        assert_eq!(read, Actor::user("u-1"));
    }
}
