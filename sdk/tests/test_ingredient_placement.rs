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

/// Returns a Context with production-like arena routing and auto-actions.
///
/// `actions_created` controls whether "c2pa.actions" is label-routed to the
/// created list, mirroring how the production settings route assertions.
fn arena_test_context(actions_created: bool) -> c2pa::Context {
    let labels = if actions_created {
        r#"["c2pa.actions", "c2pa.ingredient", "c2pa.thumbnail", "c2pa.metadata"]"#
    } else {
        r#"["c2pa.ingredient", "c2pa.thumbnail", "c2pa.metadata"]"#
    };
    let settings = c2pa::Settings::new()
        .with_toml(&format!(
            r#"
            [builder]
            created_assertion_labels = {labels}

            [builder.thumbnail]
            enabled = false

            [builder.actions.auto_opened_action]
            enabled = true

            [builder.actions.auto_placed_action]
            enabled = true
            "#
        ))
        .expect("arena test settings should be valid");
    c2pa::Context::new()
        .with_settings(settings)
        .expect("arena test context should build")
}

/// Signs with the given builder and returns the active manifest's CR-JSON.
fn sign_and_read_crjson(builder: &mut Builder) -> Result<serde_json::Value> {
    let mut source = Cursor::new(TEST_IMAGE);
    let mut dest = Cursor::new(Vec::new());
    let ed_signer = |_context: *const _, data: &[u8]| ed_sign(data, PRIVATE_KEY);
    let signer = CallbackSigner::new(ed_signer, SigningAlg::Ed25519, CERTS);
    builder.sign(&signer, "image/jpeg", &mut source, &mut dest)?;

    dest.set_position(0);
    let reader = Reader::from_stream("image/jpeg", &mut dest)?;
    Ok(serde_json::from_str(&reader.crjson())?)
}

/// Collects (assertion_key, actions_value) for every actions assertion.
fn actions_assertions(manifest: &serde_json::Value) -> Vec<(String, Vec<serde_json::Value>)> {
    manifest["assertions"]
        .as_object()
        .map(|assertions| {
            assertions
                .iter()
                .filter(|(key, _)| key.starts_with("c2pa.actions"))
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value["actions"].as_array().cloned().unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Returns the claim-list urls for one arena of the manifest.
fn claim_urls(manifest: &serde_json::Value, key: &str) -> Vec<String> {
    manifest["claim.v2"][key]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e["url"].as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn test_gathered_component_placed_lands_in_gathered_actions() -> Result<()> {
    // a gathered componentOf ingredient must still receive its mandatory
    // c2pa.placed action, but in a gathered-arena actions assertion; the
    // created actions assertion carries only the inception action
    let def = json!({
        "title": "arena.jpg",
        "format": "image/jpeg",
        "claim_generator_info": [{"name": "trufo placement test", "version": "0"}],
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.created",
                 "digitalSourceType":
                    "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"}
            ]}}
        ]
    })
    .to_string();

    let mut builder = Builder::from_context(arena_test_context(true)).with_definition(&def)?;
    builder.add_ingredient_from_stream(
        json!({
            "title": "overlay.jpg",
            "relationship": "componentOf",
            "label": "INGREDIENT_1",
            "created": false
        })
        .to_string(),
        "image/jpeg",
        &mut Cursor::new(TEST_IMAGE),
    )?;

    let crjson = sign_and_read_crjson(&mut builder)?;
    let manifest = &crjson["manifests"][0];
    let created = claim_urls(manifest, "created_assertions");
    let gathered = claim_urls(manifest, "gathered_assertions");

    // exactly one actions assertion per arena
    assert_eq!(
        created.iter().filter(|u| u.contains("c2pa.actions")).count(),
        1,
        "created: {created:?}"
    );
    assert_eq!(
        gathered.iter().filter(|u| u.contains("c2pa.actions")).count(),
        1,
        "gathered: {gathered:?}"
    );
    // the ingredient assertion itself is gathered
    assert!(gathered.iter().any(|u| u.contains("c2pa.ingredient")));

    for (key, actions) in actions_assertions(manifest) {
        let url_suffix = format!("c2pa.assertions/{key}");
        let placed: Vec<_> = actions
            .iter()
            .filter(|a| a["action"] == "c2pa.placed")
            .collect();
        if created.iter().any(|u| u.ends_with(&url_suffix)) {
            // the created actions assertion has the inception and no placed
            assert_eq!(actions[0]["action"], "c2pa.created", "{key}: {actions:?}");
            assert!(placed.is_empty(), "{key}: {actions:?}");
        } else {
            // the gathered actions assertion holds exactly the placed action,
            // referencing the gathered componentOf ingredient
            assert!(gathered.iter().any(|u| u.ends_with(&url_suffix)));
            assert_eq!(placed.len(), 1, "{key}: {actions:?}");
            let refs = &placed[0]["parameters"]["ingredients"];
            assert!(
                refs[0]["url"].as_str().unwrap_or("").contains("c2pa.ingredient"),
                "{key}: {refs:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn test_single_inception_across_created_and_gathered_actions() -> Result<()> {
    // with a created and a gathered actions assertion declared, the auto
    // inception action is inserted exactly once, in the created-arena
    // assertion only
    let def = json!({
        "title": "inception.jpg",
        "format": "image/jpeg",
        "claim_generator_info": [{"name": "trufo placement test", "version": "0"}],
        "assertions": [
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.edited"}
            ]}, "created": true},
            {"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.edited"}
            ]}}
        ]
    })
    .to_string();

    // "c2pa.actions" is excluded from created_assertion_labels, so the second
    // (unflagged) actions assertion routes gathered
    let mut builder = Builder::from_context(arena_test_context(false)).with_definition(&def)?;
    builder.add_ingredient_from_stream(
        json!({"title": "parent.jpg", "relationship": "parentOf"}).to_string(),
        "image/jpeg",
        &mut Cursor::new(TEST_IMAGE),
    )?;

    let crjson = sign_and_read_crjson(&mut builder)?;
    let manifest = &crjson["manifests"][0];
    let created = claim_urls(manifest, "created_assertions");

    let mut inception_count = 0;
    for (key, actions) in actions_assertions(manifest) {
        let inceptions = actions
            .iter()
            .filter(|a| a["action"] == "c2pa.created" || a["action"] == "c2pa.opened")
            .count();
        inception_count += inceptions;
        if inceptions > 0 {
            // the inception is first and lives in the created-arena assertion
            assert_eq!(actions[0]["action"], "c2pa.opened", "{key}: {actions:?}");
            let url_suffix = format!("c2pa.assertions/{key}");
            assert!(
                created.iter().any(|u| u.ends_with(&url_suffix)),
                "{key} not in created: {created:?}"
            );
        }
    }
    assert_eq!(inception_count, 1);
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
