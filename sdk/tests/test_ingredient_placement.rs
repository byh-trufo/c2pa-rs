// [trufo] Per-ingredient claim-list placement and file-less ingredients.

mod common;

use std::io::Cursor;

use anyhow::Result;
use c2pa::{crypto::raw_signature::SigningAlg, Builder, CallbackSigner, Reader};
use common::test_context;
use serde_json::json;

const TEST_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const CERTS: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pub");
const PRIVATE_KEY: &[u8] = include_bytes!("../tests/fixtures/certs/ed25519.pem");

fn ed_sign(data: &[u8], private_key: &[u8]) -> c2pa::Result<Vec<u8>> {
    use ed25519_dalek::{Signature, Signer, SigningKey};
    use pem::parse;

    let pem = parse(private_key).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    let key_bytes = &pem.contents()[16..];
    let signing_key =
        SigningKey::try_from(key_bytes).map_err(|e| c2pa::Error::OtherError(Box::new(e)))?;
    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Signs two file-less ingredients with opposite placement overrides and
/// returns the (created, gathered) assertion-url lists from the claim.
fn sign_and_read_lists() -> Result<(Vec<String>, Vec<String>)> {
    let def = json!({
        "title": "placement.jpg",
        "format": "image/jpeg",
        "claim_generator_info": [{"name": "trufo placement test", "version": "0"}],
        "ingredients": [
            {
                "title": "witnessed.jpg",
                "relationship": "inputTo",
                "created": true
            },
            {
                "title": "prompt.txt",
                "relationship": "inputTo",
                "data_types": [{"type": "c2pa.types.prompt"}],
                "digitalSourceType":
                    "http://c2pa.org/digitalsourcetype/trainedAlgorithmicData",
                "created": false
            }
        ],
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.created",
                 "digitalSourceType":
                    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}
            ]}}
        ]
    })
    .to_string();

    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());
    let ed_signer = |_context: *const _, data: &[u8]| ed_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);

    let mut builder = Builder::from_context(test_context()).with_definition(&def)?;
    builder.sign(&signer, "image/jpeg", &mut source, &mut dest)?;

    dest.set_position(0);
    let reader = Reader::from_stream("image/jpeg", &mut dest)?;
    let crjson: serde_json::Value = serde_json::from_str(&reader.crjson())?;
    let claim = &crjson["manifests"][0]["claim.v2"];

    let urls = |key: &str| -> Vec<String> {
        claim[key]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| e["url"].as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    Ok((urls("created_assertions"), urls("gathered_assertions")))
}

#[test]
fn test_placement_defaults_to_label_setting_when_unset() -> Result<()> {
    // without a "created" key, ingredient placement follows the
    // created_assertion_labels setting; the test settings leave it unset, so
    // the ingredient assertion defaults to gathered
    let def = serde_json::json!({
        "title": "default.jpg",
        "format": "image/jpeg",
        "claim_generator_info": [{"name": "trufo placement test", "version": "0"}],
        "ingredients": [
            {"title": "no-override.txt", "relationship": "inputTo"}
        ],
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.created",
                 "digitalSourceType":
                    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}
            ]}}
        ]
    })
    .to_string();

    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());
    let ed_signer = |_context: *const _, data: &[u8]| ed_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    let mut builder = Builder::from_context(test_context()).with_definition(&def)?;
    builder.sign(&signer, "image/jpeg", &mut source, &mut dest)?;

    dest.set_position(0);
    let reader = Reader::from_stream("image/jpeg", &mut dest)?;
    let crjson: serde_json::Value = serde_json::from_str(&reader.crjson())?;
    let claim = &crjson["manifests"][0]["claim.v2"];
    let gathered: Vec<&str> = claim["gathered_assertions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["url"].as_str())
        .collect();

    assert!(
        gathered.iter().any(|u| u.contains("c2pa.ingredient")),
        "gathered: {gathered:?}"
    );
    Ok(())
}

#[test]
fn test_per_ingredient_placement_override() -> Result<()> {
    let (created, gathered) = sign_and_read_lists()?;

    let created_ingredients: Vec<_> = created
        .iter()
        .filter(|u| u.contains("c2pa.ingredient"))
        .collect();
    let gathered_ingredients: Vec<_> = gathered
        .iter()
        .filter(|u| u.contains("c2pa.ingredient"))
        .collect();

    // one ingredient assertion in each list, per the per-ingredient override
    assert_eq!(created_ingredients.len(), 1, "created: {created:?}");
    assert_eq!(gathered_ingredients.len(), 1, "gathered: {gathered:?}");
    Ok(())
}
