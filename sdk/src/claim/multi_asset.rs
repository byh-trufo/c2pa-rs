// Copyright 2026 Trufo, Inc. All rights reserved.
// Adapted and extended by Trufo, Inc. from c2pa-rs code:
// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Multi-asset hard-binding fallback (C2PA 15.12.4).

use std::io::{self, Cursor, Read, Seek, SeekFrom};

use serde::Deserialize;

use super::{data_hash_exclusions_match_manifest, Claim, ClaimAssertion, ClaimAssetData};
use crate::{
    assertion::{Assertion, AssertionBase, AssertionData},
    assertions::{labels, BmffHash, BoxHash, DataHash},
    asset_handlers::bmff_io::{BMFFArena, XpathFetch},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    jumbf::labels::{to_absolute_uri, to_normalized_uri},
    log_item,
    read_seek::ReadSeek,
    status_tracker::StatusTracker,
    store::StoreValidationInfo,
    utils::hash_utils::{hash_size_by_alg, vec_compare, HashRange},
    validation_status::{
        ALGORITHM_UNSUPPORTED, ASSERTION_MULTI_ASSET_HASH_MALFORMED as MALFORMED,
        ASSERTION_MULTI_ASSET_HASH_MATCH as MATCH, ASSERTION_MULTI_ASSET_HASH_MISMATCH as MISMATCH,
        ASSERTION_MULTI_ASSET_HASH_MISSING_PART as MISSING_PART,
    },
    HashedUri,
};

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
struct MultiAssetHash {
    parts: Vec<Part>,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase")]
struct Part {
    location: Location,
    hash_assertion: HashedUri,
    #[serde(default)]
    optional: bool,
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(untagged, deny_unknown_fields)]
enum Location {
    Bytes {
        #[serde(rename = "byteOffset")]
        byte_offset: u64,
        length: u64,
    },
    Bmff {
        #[serde(rename = "bmffBox")]
        path: String,
    },
}

fn failure(code: &str) -> Error {
    Error::C2PAValidation(code.to_owned())
}

fn same_uri(claim: &Claim, uri: &str, target: &str) -> bool {
    to_normalized_uri(&to_absolute_uri(claim.label(), uri)) == to_normalized_uri(target)
}

// require the signed claim's reference before using an assertion as a binding
fn authenticated(claim: &Claim, assertion: &ClaimAssertion) -> bool {
    let target = claim.assertion_uri(&assertion.label());
    let mut found = false;
    for reference in claim
        .assertions()
        .iter()
        .filter(|r| same_uri(claim, &r.url(), &target))
    {
        found = true;
        if reference.alg().as_deref().unwrap_or(claim.alg()) != assertion.hash_alg()
            || !vec_compare(&reference.hash(), assertion.hash())
        {
            return false;
        }
    }
    found
}

impl Claim {
    pub(super) fn verify_multi_asset_hash(
        &self,
        asset: &mut ClaimAssetData<'_>,
        svi: &StoreValidationInfo,
        log: &mut StatusTracker,
        context: &Context,
    ) -> Result<bool> {
        if !self
            .assertion_store
            .iter()
            .any(|a| a.label_raw() == labels::MULTI_ASSET_HASH)
        {
            return Ok(false);
        }
        let format = asset.format().ok_or(Error::UnsupportedType)?;
        let result = match asset {
            #[cfg(feature = "file_io")]
            ClaimAssetData::Path(path) => {
                self.verify_parts(&mut std::fs::File::open(path)?, &format, svi, context)
            }
            ClaimAssetData::Bytes(bytes, _) => {
                self.verify_parts(&mut Cursor::new(*bytes), &format, svi, context)
            }
            ClaimAssetData::Stream(stream, _) => self.verify_parts(*stream, &format, svi, context),
            _ => return Err(Error::UnsupportedType),
        };
        let item = log_item!(
            self.assertion_uri(labels::MULTI_ASSET_HASH),
            "multi-asset hash",
            "verify_hash_binding"
        );
        match result {
            Ok(()) => {
                item.validation_status(MATCH).success(log);
            }
            Err(Error::OperationCancelled) => return Err(Error::OperationCancelled),
            Err(e) => {
                let code = match &e {
                    Error::C2PAValidation(code) => match code.as_str() {
                        MALFORMED => MALFORMED,
                        MISSING_PART => MISSING_PART,
                        ALGORITHM_UNSUPPORTED => ALGORITHM_UNSUPPORTED,
                        _ => MISMATCH,
                    },
                    Error::UnsupportedType => ALGORITHM_UNSUPPORTED,
                    _ => MISMATCH,
                };
                item.validation_status(code).failure(log, e)?;
            }
        }
        Ok(true)
    }

    fn verify_parts(
        &self,
        stream: &mut dyn ReadSeek,
        format: &str,
        svi: &StoreValidationInfo,
        context: &Context,
    ) -> Result<()> {
        let mut candidates = self
            .assertion_store
            .iter()
            .filter(|a| a.label_raw() == labels::MULTI_ASSET_HASH);
        let assertion = candidates.next().ok_or_else(|| failure(MALFORMED))?;
        if candidates.next().is_some() || !authenticated(self, assertion) {
            return Err(failure(MALFORMED));
        }
        let AssertionData::Cbor(data) = assertion.assertion().decode_data() else {
            return Err(failure(MALFORMED));
        };
        let multi: MultiAssetHash = c2pa_cbor::from_slice(data).map_err(|_| failure(MALFORMED))?;
        if multi.parts.is_empty() {
            return Err(failure(MALFORMED));
        }
        let asset_length = stream.seek(SeekFrom::End(0))?;
        let mut bmff = None;
        let mut covered = 0;
        let mut located = Vec::with_capacity(multi.parts.len());
        for part in &multi.parts {
            let (start, length) = match &part.location {
                Location::Bytes {
                    byte_offset,
                    length,
                } => (*byte_offset, *length),
                Location::Bmff { path } => {
                    if bmff.is_none() {
                        bmff = Some(
                            BMFFArena::from_stream(stream)
                                .map_err(|_| failure(MALFORMED))?
                                .0,
                        );
                    }
                    let arena = bmff.as_ref().ok_or_else(|| failure(MALFORMED))?;
                    let tokens = arena
                        .fetch(path)
                        .map_err(|_| failure(MALFORMED))?
                        .ok_or_else(|| failure(MALFORMED))?;
                    let [token] = tokens.as_slice() else {
                        return Err(failure(MALFORMED));
                    };
                    let info = &arena.get(*token).ok_or_else(|| failure(MALFORMED))?.data;
                    (info.offset, info.size)
                }
            };
            let end = start
                .checked_add(length)
                .ok_or_else(|| failure(MALFORMED))?;
            let reference = &part.hash_assertion;
            let (label, instance) = Claim::assertion_label_from_link(&reference.url());
            let binding = self
                .get_claim_assertion(&label, instance)
                .ok_or_else(|| failure(MALFORMED))?;
            let algorithm = reference.alg().unwrap_or_else(|| self.alg().to_owned());
            hash_size_by_alg(&algorithm).map_err(|_| failure(ALGORITHM_UNSUPPORTED))?;
            let hash = if algorithm == binding.hash_alg() {
                binding.hash().to_vec()
            } else {
                Claim::calc_assertion_box_hash(
                    &binding.label(),
                    binding.assertion(),
                    binding.salt().clone(),
                    &algorithm,
                )?
            };
            if !same_uri(
                self,
                &reference.url(),
                &self.assertion_uri(&binding.label()),
            ) || !binding
                .label_raw()
                .strip_suffix(labels::PART)
                .is_some_and(|label| {
                    matches!(
                        labels::parse_label(label).0,
                        labels::DATA_HASH | labels::BOX_HASH | labels::BMFF_HASH
                    )
                })
                || !authenticated(self, binding)
                || !vec_compare(&reference.hash(), &hash)
            {
                return Err(failure(MALFORMED));
            }
            if start > asset_length || (start == asset_length && length > 0) {
                if part.optional {
                    continue;
                }
                return Err(failure(MISSING_PART));
            }
            if start != covered {
                return Err(failure(MALFORMED));
            }
            if end > asset_length {
                return Err(failure(MISMATCH));
            }
            covered = end;
            located.push((start, length, binding));
        }
        if covered != asset_length {
            return Err(failure(MALFORMED));
        }
        for (start, length, binding) in located {
            let mut reader = PartReader::new(stream, start, length)?;
            let mut progress = |step, total| {
                context.check_progress(ProgressPhase::VerifyingAssetHash, step, total)
            };
            // the part suffix follows the version, e.g. c2pa.hash.bmff.v2.part
            let label = binding.label_raw();
            let (label, version, _) = labels::parse_label(label.trim_end_matches(labels::PART));
            let assertion = Assertion::new(
                label,
                Some(version),
                binding.assertion().decode_data().clone(),
            );
            match label {
                labels::DATA_HASH => {
                    let hash =
                        DataHash::from_assertion(&assertion).map_err(|_| failure(MALFORMED))?;
                    if hash.is_remote_hash()
                        || hash.exclusions.as_ref().is_some_and(|ranges| {
                            ranges.iter().any(|r| {
                                r.start()
                                    .checked_add(r.length())
                                    .is_none_or(|end| end > length)
                            })
                        })
                    {
                        return Err(failure(MALFORMED));
                    }
                    let range = svi
                        .manifest_store_range
                        .as_ref()
                        .filter(|r| r.start() >= start && r.start() < start + length)
                        .map(|r| HashRange::new(r.start() - start, r.length()));
                    if hash.exclusions.as_ref().is_some_and(|ranges| {
                        !data_hash_exclusions_match_manifest(
                            ranges,
                            range.as_ref(),
                            svi.is_embedded && svi.manifest_store_range.is_none(),
                        )
                    }) {
                        return Err(failure(MISMATCH));
                    }
                    hash.verify_stream_hash_with_progress(
                        &mut reader,
                        Some(self.alg()),
                        &mut progress,
                    )?;
                }
                labels::BOX_HASH => {
                    let hash =
                        BoxHash::from_assertion(&assertion).map_err(|_| failure(MALFORMED))?;
                    let processor = context
                        .io()
                        .handler(format)
                        .and_then(|h| h.asset_box_hash_ref())
                        .ok_or_else(|| failure(MALFORMED))?;
                    hash.verify_stream_hash_with_progress(
                        &mut reader,
                        Some(self.alg()),
                        processor,
                        &mut progress,
                    )?;
                }
                _ => {
                    let hash =
                        BmffHash::from_assertion(&assertion).map_err(|_| failure(MALFORMED))?;
                    hash.verify_stream_hash_with_progress(
                        &mut reader,
                        Some(self.alg()),
                        &mut progress,
                    )?;
                }
            }
        }
        Ok(())
    }
}

// adapt the existing hash verifiers to part-relative offsets without copying bytes
struct PartReader<'a> {
    source: &'a mut dyn ReadSeek,
    start: u64,
    length: u64,
    position: u64,
}

impl<'a> PartReader<'a> {
    fn new(source: &'a mut dyn ReadSeek, start: u64, length: u64) -> io::Result<Self> {
        source.seek(SeekFrom::Start(start))?;
        Ok(Self {
            source,
            start,
            length,
            position: 0,
        })
    }
}

impl Read for PartReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let limit = (self.length - self.position).min(buffer.len() as u64) as usize;
        let count = self.source.read(&mut buffer[..limit])?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for PartReader<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        if position < 0 || position > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside asset part",
            ));
        }
        let position = position as u64;
        self.source.seek(SeekFrom::Start(self.start + position))?;
        self.position = position;
        Ok(position)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use super::*;
    use crate::{
        assertions::{labels, DataHash, UserCbor},
        claim::{Claim, ClaimAssetData},
        status_tracker::{ErrorBehavior, StatusTracker},
        store::StoreValidationInfo,
        Context,
    };

    fn multipart(change: impl FnOnce(&mut MultiAssetHash)) -> Claim {
        let mut claim = Claim::new("multipart test", Some("test"), 1);
        let mut multi = MultiAssetHash { parts: vec![] };
        for (index, bytes) in b"abcdefghijkl".chunks(4).enumerate() {
            let mut hash = DataHash::new("part", "sha256");
            hash.gen_hash_from_stream(&mut Cursor::new(bytes)).unwrap();
            multi.parts.push(Part {
                location: Location::Bytes {
                    byte_offset: index as u64 * 4,
                    length: 4,
                },
                hash_assertion: claim
                    .add_assertion(&UserCbor::new(
                        "c2pa.hash.data.part",
                        c2pa_cbor::to_vec(&hash).unwrap(),
                    ))
                    .unwrap(),
                optional: index > 0,
            });
        }
        change(&mut multi);
        bind(
            &mut claim,
            c2pa_cbor::to_vec(&multi).unwrap(),
            b"abcdefghijkl",
        );
        claim
    }

    fn bind(claim: &mut Claim, payload: Vec<u8>, whole: &[u8]) {
        claim
            .add_assertion(&UserCbor::new(labels::MULTI_ASSET_HASH, payload))
            .unwrap();
        let mut ordinary = DataHash::new("asset", "sha256");
        ordinary
            .gen_hash_from_stream(&mut Cursor::new(whole))
            .unwrap();
        claim.add_assertion(&ordinary).unwrap();
    }

    #[test]
    fn multipart_binding_results() {
        for (bytes, required, expected) in [
            (&b"abcdefghijkl"[..], false, "assertion.dataHash.match"),
            (&b"abcdefgh"[..], false, "assertion.multiAssetHash.match"),
            (&b"abcd"[..], false, "assertion.multiAssetHash.match"),
            (&b"abcdXfgh"[..], false, "assertion.multiAssetHash.mismatch"),
            (&b"abcdef"[..], false, "assertion.multiAssetHash.mismatch"),
            (&b"abcd"[..], true, "assertion.multiAssetHash.missingPart"),
            (
                &b"abcdefghijklm"[..],
                false,
                "assertion.multiAssetHash.malformed",
            ),
        ] {
            let claim = multipart(|multi| multi.parts[1].optional = !required);
            check(&claim, bytes, expected);
        }
    }

    fn check(claim: &Claim, bytes: &[u8], expected: &str) {
        let svi = StoreValidationInfo {
            binding_claim: claim.label().to_owned(),
            ..Default::default()
        };
        for stop_on_error in [false, true] {
            let mut cursor = Cursor::new(bytes);
            let inputs = [
                ClaimAssetData::Bytes(bytes, "image/jpeg"),
                ClaimAssetData::Stream(&mut cursor, "image/jpeg"),
            ];
            #[cfg(feature = "file_io")]
            let directory = tempfile::tempdir().unwrap();
            #[cfg(feature = "file_io")]
            let path = directory.path().join("multipart.jpg");
            #[cfg(feature = "file_io")]
            std::fs::write(&path, bytes).unwrap();
            let inputs = inputs.into_iter();
            #[cfg(feature = "file_io")]
            let inputs = inputs.chain(std::iter::once(ClaimAssetData::Path(&path)));
            for mut input in inputs {
                let mut report = StatusTracker::with_error_behavior(if stop_on_error {
                    ErrorBehavior::StopOnFirstError
                } else {
                    ErrorBehavior::ContinueWhenPossible
                });
                let result = Claim::verify_hash_binding(
                    claim,
                    &mut input,
                    &svi,
                    &mut report,
                    &Context::new(),
                );
                assert!(
                    report.has_status(expected),
                    "{expected}: {:?}",
                    report.logged_items()
                );
                assert!(!report.has_status(MATCH) || expected == MATCH);
                if expected.starts_with("assertion.multiAssetHash") {
                    assert!(!report.has_status("assertion.dataHash.mismatch"));
                }
                assert_eq!(
                    result.is_err(),
                    stop_on_error && !expected.ends_with(".match")
                );
            }
        }
    }

    #[test]
    fn multipart_structure_and_references() {
        for case in [
            "gap",
            "overlap",
            "empty",
            "external",
            "wrong_hash",
            "duplicate",
            "unclaimed_multi",
            "unclaimed_part",
            "unauthenticated_multi",
        ] {
            let mut claim = multipart(|multi| match case {
                "gap" => {
                    multi.parts[1].location = Location::Bytes {
                        byte_offset: 5,
                        length: 4,
                    }
                }
                "overlap" => {
                    multi.parts[1].location = Location::Bytes {
                        byte_offset: 3,
                        length: 4,
                    }
                }
                "empty" => multi.parts.clear(),
                "external" => {
                    multi.parts[1].hash_assertion = HashedUri::new(
                        "self#jumbf=/c2pa/other/c2pa.assertions/c2pa.hash.data.part".to_owned(),
                        None,
                        &[0; 32],
                    )
                }
                "wrong_hash" => multi.parts[1].hash_assertion.update_hash(vec![0; 32]),
                _ => (),
            });
            match case {
                "duplicate" => {
                    let data = claim.assertion_store[3].assertion().data().to_vec();
                    claim
                        .add_assertion(&UserCbor::new(labels::MULTI_ASSET_HASH, data))
                        .unwrap();
                }
                "unclaimed_multi" => {
                    claim.assertions.remove(3);
                }
                "unclaimed_part" => {
                    claim.assertions.remove(1);
                }
                "unauthenticated_multi" => {
                    claim.assertions[3].update_hash(vec![0; 32]);
                }
                _ => (),
            }
            check(&claim, b"abcdefgh", MALFORMED);
        }
    }

    #[test]
    fn multipart_schema() {
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"parts": []}),
            serde_json::json!({"parts": [{}]}),
            serde_json::json!({"parts": [{"location": {"byteOffset": -1, "length": 4}}]}),
        ] {
            let mut claim = Claim::new("schema test", Some("test"), 1);
            bind(
                &mut claim,
                c2pa_cbor::to_vec(&payload).unwrap(),
                b"abcdefghijkl",
            );
            check(&claim, b"abcdefgh", MALFORMED);
        }
    }

    #[test]
    fn multipart_hash_methods_and_relative_offsets() {
        let bmff = b"\0\0\0\x18ftypisom\0\0\0\0isommp42\0\0\0\x0cmdatDATA";
        let jpeg = include_bytes!("../../tests/fixtures/no_manifest.jpg");
        let context = Context::new();
        for (label, bytes) in [
            ("c2pa.hash.boxes.part", &jpeg[..]),
            ("c2pa.hash.bmff.v2.part", &bmff[..]),
        ] {
            let mut claim = Claim::new("part methods", Some("test"), 1);
            let mut hash = DataHash::new("prefix", "sha256");
            hash.gen_hash_from_stream(&mut Cursor::new(b"HEAD"))
                .unwrap();
            let prefix = claim
                .add_assertion(&UserCbor::new(
                    "c2pa.hash.data.part",
                    c2pa_cbor::to_vec(&hash).unwrap(),
                ))
                .unwrap();
            let data = if label.contains("boxes") {
                let mut hash = BoxHash { boxes: vec![] };
                let processor = context
                    .io()
                    .handler("image/jpeg")
                    .unwrap()
                    .asset_box_hash_ref()
                    .unwrap();
                hash.generate_box_hash_from_stream(
                    &mut Cursor::new(bytes),
                    "sha256",
                    processor,
                    false,
                )
                .unwrap();
                c2pa_cbor::to_vec(&hash).unwrap()
            } else {
                let mut hash = BmffHash::new("part", "sha256", None);
                hash.set_bmff_version(2);
                hash.set_default_exclusions();
                hash.gen_hash_from_stream(&mut Cursor::new(bytes)).unwrap();
                c2pa_cbor::to_vec(&hash).unwrap()
            };
            let reference = claim.add_assertion(&UserCbor::new(label, data)).unwrap();
            let binding = claim.assertion_store.last().unwrap();
            let hash = Claim::calc_assertion_box_hash(
                &binding.label(),
                binding.assertion(),
                binding.salt().clone(),
                "sha384",
            )
            .unwrap();
            let reference = HashedUri::new(reference.url(), Some("sha384".to_owned()), &hash);
            let multi = MultiAssetHash {
                parts: vec![
                    Part {
                        location: Location::Bytes {
                            byte_offset: 0,
                            length: 4,
                        },
                        hash_assertion: prefix,
                        optional: false,
                    },
                    Part {
                        location: Location::Bytes {
                            byte_offset: 4,
                            length: bytes.len() as u64,
                        },
                        hash_assertion: reference,
                        optional: false,
                    },
                ],
            };
            let mut asset = b"HEAD".to_vec();
            asset.extend_from_slice(bytes);
            let mut original = asset.clone();
            original.extend_from_slice(b"TAIL");
            bind(&mut claim, c2pa_cbor::to_vec(&multi).unwrap(), &original);
            check(&claim, &asset, MATCH);
        }

        let mut claim = Claim::new("box locators", Some("test"), 1);
        let mut multi = MultiAssetHash { parts: vec![] };
        for (path, bytes) in [("/ftyp", &bmff[..24]), ("/mdat", &bmff[24..])] {
            let mut hash = DataHash::new("box", "sha256");
            hash.gen_hash_from_stream(&mut Cursor::new(bytes)).unwrap();
            let reference = claim
                .add_assertion(&UserCbor::new(
                    "c2pa.hash.data.part",
                    c2pa_cbor::to_vec(&hash).unwrap(),
                ))
                .unwrap();
            multi.parts.push(Part {
                location: Location::Bmff {
                    path: path.to_owned(),
                },
                hash_assertion: reference,
                optional: false,
            });
        }
        bind(
            &mut claim,
            c2pa_cbor::to_vec(&multi).unwrap(),
            b"former asset",
        );
        check(&claim, bmff, MATCH);
    }

    #[test]
    fn multipart_cancellation_and_reader_bounds() {
        let claim = multipart(|_| ());
        let context = Context::new().with_progress_callback(|_, _, _| false);
        assert!(matches!(
            claim.verify_multi_asset_hash(
                &mut ClaimAssetData::Bytes(b"abcdefgh", "image/jpeg"),
                &StoreValidationInfo::default(),
                &mut StatusTracker::default(),
                &context
            ),
            Err(Error::OperationCancelled)
        ));
        let mut source = Cursor::new(b"0123456789");
        let mut reader = PartReader::new(&mut source, 3, 4).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"3456");
        assert_eq!(reader.seek(SeekFrom::End(-2)).unwrap(), 2);
        assert_eq!(reader.seek(SeekFrom::Current(-1)).unwrap(), 1);
        assert!(reader.seek(SeekFrom::Start(5)).is_err());
        assert!(reader.seek(SeekFrom::Current(-2)).is_err());
        assert_eq!(reader.stream_position().unwrap(), 1);
    }

    #[test]
    fn multipart_cannot_recover_an_invalid_manifest_exclusion() {
        let mut claim = Claim::new("exclusions", Some("test"), 1);
        let mut hash = DataHash::new("part", "sha256");
        hash.gen_hash_from_stream(&mut Cursor::new(b"abcdefgh"))
            .unwrap();
        let reference = claim
            .add_assertion(&UserCbor::new(
                "c2pa.hash.data.part",
                c2pa_cbor::to_vec(&hash).unwrap(),
            ))
            .unwrap();
        hash.add_exclusion(HashRange::new(0, 1));
        hash.gen_hash_from_stream(&mut Cursor::new(b"abcdefghijkl"))
            .unwrap();
        claim.add_assertion(&hash).unwrap();
        let multi = MultiAssetHash {
            parts: vec![Part {
                location: Location::Bytes {
                    byte_offset: 0,
                    length: 8,
                },
                hash_assertion: reference,
                optional: false,
            }],
        };
        claim
            .add_assertion(&UserCbor::new(
                labels::MULTI_ASSET_HASH,
                c2pa_cbor::to_vec(&multi).unwrap(),
            ))
            .unwrap();
        check(&claim, b"abcdefgh", "assertion.dataHash.mismatch");
    }
}
