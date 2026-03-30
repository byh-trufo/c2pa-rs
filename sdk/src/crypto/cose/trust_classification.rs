// [trufo] Trust classification for openprov.
//
// Classifies signing and TSA certificate chains against named trust pools
// and returns structured results with trust codes and chain metadata.

#![allow(missing_docs)]

use asn1_rs::{FromDer, Oid};
use serde::{Deserialize, Serialize};
use x509_parser::{certificate::X509Certificate, extensions::ParsedExtension, pem::Pem, prelude::*};

use super::CertificateTrustPolicy;

// --- OID constants ---

/// C2PA Assurance Level extension OID prefix: 1.3.6.1.4.1.62558.3
const C2PA_ASSURANCE_LEVEL_OID_PREFIX: &str = "1.3.6.1.4.1.62558.3";
/// C2PA Assurance Level 1: 1.3.6.1.4.1.62558.3.10
const C2PA_ASSURANCE_LEVEL_1: &str = "1.3.6.1.4.1.62558.3.10";
/// C2PA Assurance Level 2: 1.3.6.1.4.1.62558.3.20
const C2PA_ASSURANCE_LEVEL_2: &str = "1.3.6.1.4.1.62558.3.20";
/// documentSigning EKU: 1.3.6.1.5.5.7.3.36
const EKU_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";

// --- Trust code constants ---

pub const TRUST_C2PA_LEVEL_2: &str = "openprov.trust.c2pa.level-2";
pub const TRUST_C2PA_LEVEL_1: &str = "openprov.trust.c2pa.level-1";
// dead code path for now — requires C2PA interim trust list
pub const TRUST_C2PA_INTERIM: &str = "openprov.trust.c2pa.interim";
pub const TRUST_CAWG_INTERIM: &str = "openprov.trust.cawg.interim";
pub const TRUST_UNKNOWN: &str = "openprov.trust.unknown";

// --- Timestamp code constants ---

pub const TIMESTAMP_TRUSTED: &str = "openprov.timestamp.trusted";
pub const TIMESTAMP_UNKNOWN: &str = "openprov.timestamp.unknown";
pub const TIMESTAMP_NONE: &str = "openprov.timestamp.none";

// --- Output structs ---

/// Distinguished name fields from an X.509 certificate.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
pub struct CertDn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub o: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ou: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c: Option<String>,
}

/// A single entry in a certificate chain (leaf to root).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
pub struct ChainEntry {
    pub dn: CertDn,
    /// RFC 3339 timestamp of the certificate's notAfter field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Trust classification result for a signing chain.
///
/// Contains the main trust code, the timestamp trust code, and the
/// certificate chain metadata (DN + validity, leaf to root).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
pub struct TrustResult {
    /// Main trust code (e.g. `openprov.trust.c2pa.level-2`).
    pub trust: String,
    /// Certificate chain metadata (leaf to root).
    pub chain: Vec<ChainEntry>,
    /// Timestamp trust code (e.g. `openprov.timestamp.trusted`).
    pub timestamp: String,
}

/// Trust classification for a single CAWG identity assertion.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
pub struct IdentityTrustEntry {
    /// The assertion label (e.g. `cawg.identity` or `cawg.identity__2`).
    pub label: String,
    /// Trust classification for this identity assertion's signing chain.
    #[serde(flatten)]
    pub result: TrustResult,
}

/// Combined trust classification for a manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "json_schema", derive(schemars::JsonSchema))]
pub struct TrustClassification {
    /// The manifest label (URN).
    pub label: String,
    /// Trust classification for the C2PA claim-signing chain.
    pub claim: TrustResult,
    /// Trust classification for each CAWG identity assertion (may be empty).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub identities: Vec<IdentityTrustEntry>,
}

// --- Internal helpers ---

/// Extract DN from an X.509 certificate.
fn extract_dn(cert: &X509Certificate) -> CertDn {
    let cn = cert
        .subject()
        .iter_common_name()
        .filter_map(|attr| attr.as_str().ok())
        .last()
        .map(|s| s.to_string());
    let o = cert
        .subject()
        .iter_organization()
        .filter_map(|attr| attr.as_str().ok())
        .last()
        .map(|s| s.to_string());
    let ou = cert
        .subject()
        .iter_organizational_unit()
        .filter_map(|attr| attr.as_str().ok())
        .last()
        .map(|s| s.to_string());
    let c = cert
        .subject()
        .iter_country()
        .filter_map(|attr| attr.as_str().ok())
        .last()
        .map(|s| s.to_string());
    CertDn { cn, o, ou, c }
}

/// Build chain entries (DN + valid_until) from DER cert bytes.
fn build_chain_entries(chain_der: &[Vec<u8>]) -> Vec<ChainEntry> {
    chain_der
        .iter()
        .filter_map(|der| {
            let (_rem, cert) = X509Certificate::from_der(der).ok()?;
            let dn = extract_dn(&cert);
            let ts = cert.validity().not_after.timestamp();
            let valid_until = chrono::DateTime::from_timestamp(ts, 0)
                .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
            Some(ChainEntry { dn, valid_until })
        })
        .collect()
}

/// Parse PEM-encoded certificate bytes into DER vectors.
fn pem_to_der_chain(pem_bytes: &[u8]) -> Vec<Vec<u8>> {
    Pem::iter_from_buffer(pem_bytes)
        .filter_map(|r| r.ok())
        .map(|pem| pem.contents)
        .collect()
}

/// Check if a DER-encoded leaf cert has the C2PA assurance level extension
/// and return the trust code.
fn classify_c2pa_assurance(leaf_der: &[u8]) -> &'static str {
    let Ok((_rem, cert)) = X509Certificate::from_der(leaf_der) else {
        return TRUST_UNKNOWN;
    };

    for ext in cert.extensions() {
        let oid_str = ext.oid.to_string();
        if oid_str.starts_with(C2PA_ASSURANCE_LEVEL_OID_PREFIX) {
            if let Ok((_rem, oid)) = Oid::from_der(ext.value) {
                let level_str = oid.to_string();
                if level_str == C2PA_ASSURANCE_LEVEL_2 {
                    return TRUST_C2PA_LEVEL_2;
                } else if level_str == C2PA_ASSURANCE_LEVEL_1 {
                    return TRUST_C2PA_LEVEL_1;
                }
            }
            return TRUST_UNKNOWN;
        }
    }

    TRUST_UNKNOWN
}

/// Check if a DER-encoded leaf cert has the documentSigning EKU.
fn has_document_signing_eku(leaf_der: &[u8]) -> bool {
    let Ok((_rem, cert)) = X509Certificate::from_der(leaf_der) else {
        return false;
    };

    for ext in cert.extensions() {
        if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
            for oid in &eku.other {
                if oid.to_string() == EKU_DOCUMENT_SIGNING {
                    return true;
                }
            }
        }
    }
    false
}

/// Check whether a trust pool has any anchors loaded.
fn has_anchors(ctp: &CertificateTrustPolicy) -> bool {
    ctp.trust_anchor_ders().next().is_some()
}

/// Try to verify a cert chain against a trust pool.
fn is_chain_trusted(
    chain_der: &[Vec<u8>],
    signing_time: Option<i64>,
    ctp: &CertificateTrustPolicy,
) -> bool {
    if chain_der.is_empty() || !has_anchors(ctp) {
        return false;
    }
    let end_entity_cert_der = &chain_der[0];
    let intermediates = &chain_der[1..];
    ctp.check_certificate_trust(intermediates, end_entity_cert_der, signing_time)
        .is_ok()
}

// --- Public API ---

/// Classify trust for the manifest's claim-signing and TSA certificate chains,
/// plus all CAWG identity assertions.
///
/// `manifest_label` is the manifest URN.
/// `signing_chain_pem` and `tsa_chain_pem` are PEM-encoded cert chains
/// (leaf first) as produced by c2pa-rs `dump_cert_chain`.
/// `cawg_chains` is a slice of `(label, pem_bytes)` pairs, one per
/// `cawg.identity` assertion found in the manifest.
pub fn classify_trust(
    manifest_label: &str,
    signing_chain_pem: &[u8],
    tsa_chain_pem: &[u8],
    signing_time: Option<i64>,
    c2pa_ctp: &CertificateTrustPolicy,
    ctsa_ctp: &CertificateTrustPolicy,
    cawg_chains: &[(String, Vec<u8>)],
) -> TrustClassification {
    let signing_chain_der = pem_to_der_chain(signing_chain_pem);
    let tsa_chain_der = pem_to_der_chain(tsa_chain_pem);

    // C2PA claim: verify signing chain, then read assurance level OID
    let c2pa_trust = if is_chain_trusted(&signing_chain_der, signing_time, c2pa_ctp) {
        classify_c2pa_assurance(&signing_chain_der[0])
    } else {
        TRUST_UNKNOWN
    };

    // timestamp: verify TSA chain against CTSA trust anchors
    let tsa_trust = if tsa_chain_der.is_empty() {
        TIMESTAMP_NONE
    } else if is_chain_trusted(&tsa_chain_der, signing_time, ctsa_ctp) {
        TIMESTAMP_TRUSTED
    } else {
        TIMESTAMP_UNKNOWN
    };

    // CAWG identity assertions
    let identities = cawg_chains
        .iter()
        .map(|(label, pem)| {
            let chain_der = pem_to_der_chain(pem);
            let trust = if !chain_der.is_empty() && has_document_signing_eku(&chain_der[0]) {
                TRUST_CAWG_INTERIM
            } else {
                TRUST_UNKNOWN
            };
            IdentityTrustEntry {
                label: label.to_string(),
                result: TrustResult {
                    trust: trust.to_string(),
                    chain: build_chain_entries(&chain_der),
                    // CAWG timestamps not yet classified
                    timestamp: TIMESTAMP_NONE.to_string(),
                },
            }
        })
        .collect();

    TrustClassification {
        label: manifest_label.to_string(),
        claim: TrustResult {
            trust: c2pa_trust.to_string(),
            chain: build_chain_entries(&signing_chain_der),
            timestamp: tsa_trust.to_string(),
        },
        identities,
    }
}
