// Copyright 2023 Adobe. All rights reserved.
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

use std::{
    fs::{File, OpenOptions},
    io::Cursor,
    path::Path,
};

use crate::{
    asset_handlers::pdf::{C2paPdf, Pdf},
    asset_io::{
        rename_or_move, AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter,
        ComposedManifestRef, HashBlockObjectType, HashObjectPositions,
    },
    utils::io_utils::tempfile_builder,
    Error::{self, JumbfNotFound, NotImplemented, PdfReadError},
};

static SUPPORTED_TYPES: [&str; 2] = ["pdf", "application/pdf"];
static LOCATION_MARKER: &[u8] = b"TRUFO_C2PA_PDF_MARKER_9D4B6F11A2C3E57A";

pub struct PdfIO {}

impl CAIReader for PdfIO {
    fn read_cai(&self, asset_reader: &mut dyn CAIRead) -> crate::Result<Vec<u8>> {
        asset_reader.rewind()?;

        let pdf = Pdf::from_reader(asset_reader).map_err(|e| Error::InvalidAsset(e.to_string()))?;
        self.read_manifest_bytes(pdf)
    }

    fn read_xmp(&self, asset_reader: &mut dyn CAIRead) -> Option<String> {
        if asset_reader.rewind().is_err() {
            return None;
        }

        let Ok(pdf) = Pdf::from_reader(asset_reader) else {
            return None;
        };

        self.read_xmp_from_pdf(pdf)
    }
}

impl PdfIO {
    fn find_unique_subslice(haystack: &[u8], needle: &[u8]) -> crate::Result<usize> {
        if needle.is_empty() {
            return Err(Error::InvalidAsset(
                "embedded C2PA manifest in PDF is empty".to_string(),
            ));
        }

        let mut matches = haystack
            .windows(needle.len())
            .enumerate()
            .filter_map(|(idx, window)| (window == needle).then_some(idx));

        let Some(first) = matches.next() else {
            return Err(Error::InvalidAsset(
                "unable to locate embedded C2PA manifest bytes in PDF".to_string(),
            ));
        };

        if matches.next().is_some() {
            return Err(Error::InvalidAsset(
                "embedded C2PA manifest bytes appear multiple times in PDF".to_string(),
            ));
        }

        Ok(first)
    }

    fn read_manifest_bytes(&self, pdf: impl C2paPdf) -> crate::Result<Vec<u8>> {
        let Ok(result) = pdf.read_manifest_bytes() else {
            return Err(PdfReadError);
        };

        let Some(bytes) = result else {
            return Err(JumbfNotFound);
        };

        match bytes.as_slice() {
            [bytes] => Ok(bytes.to_vec()),
            _ => Err(NotImplemented(
                "c2pa-rs only supports reading PDFs with one manifest".into(),
            )),
        }
    }

    fn read_xmp_from_pdf(&self, pdf: impl C2paPdf) -> Option<String> {
        pdf.read_xmp()
    }

    fn locate_manifest_range_in_bytes(
        &self,
        input_bytes: &[u8],
    ) -> crate::Result<Option<(usize, usize)>> {
        let mut cursor = Cursor::new(input_bytes.to_vec());
        let pdf = Pdf::from_reader(&mut cursor).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        match pdf.read_manifest_bytes() {
            Ok(Some(manifests)) => {
                let manifest_bytes = match manifests.as_slice() {
                    [single] => *single,
                    _ => {
                        return Err(Error::NotImplemented(
                            "c2pa-rs only supports PDFs with one manifest".into(),
                        ))
                    }
                };

                let start = Self::find_unique_subslice(input_bytes, manifest_bytes)?;

                Ok(Some((start, manifest_bytes.len())))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Error::InvalidAsset(e.to_string())),
        }
    }
}

impl AssetIO for PdfIO {
    fn new(_asset_type: &str) -> Self
    where
        Self: Sized,
    {
        Self {}
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(PdfIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn CAIWriter>> {
        Some(Box::new(PdfIO::new(asset_type)))
    }

    fn read_cai_store(&self, asset_path: &Path) -> crate::Result<Vec<u8>> {
        let mut f = File::open(asset_path)?;
        self.read_cai(&mut f)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> crate::Result<()> {
        let mut input_stream = OpenOptions::new().read(true).write(true).open(asset_path)?;
        let mut temp_file = tempfile_builder("c2pa_temp")?;
        self.write_cai(&mut input_stream, &mut temp_file, store_bytes)?;
        rename_or_move(temp_file, asset_path)
    }

    fn get_object_locations(&self, asset_path: &Path) -> crate::Result<Vec<HashObjectPositions>> {
        let mut f = File::open(asset_path)?;
        self.get_object_locations_from_stream(&mut f)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> crate::Result<()> {
        self.save_cai_store(asset_path, &[])
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        Some(self)
    }
}

impl CAIWriter for PdfIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> crate::Result<()> {
        input_stream.rewind()?;

        let mut input_bytes = Vec::new();
        input_stream.read_to_end(&mut input_bytes)?;

        // deterministic fast path for final pass updates: patch bytes in place
        // when replacing an existing manifest with one of the same size
        if !store_bytes.is_empty() {
            if let Some((start, length)) = self.locate_manifest_range_in_bytes(&input_bytes)? {
                if store_bytes.len() == length {
                    let mut out_bytes = input_bytes;
                    out_bytes[start..start + length].copy_from_slice(store_bytes);
                    return output_stream.write_all(&out_bytes).map_err(Error::IoError);
                }
            }
        }

        // structural path (first embed, remove, or size-changing replacement)
        let mut parse_cursor = Cursor::new(input_bytes);
        let mut pdf = Pdf::from_reader(&mut parse_cursor).map_err(|e| Error::InvalidAsset(e.to_string()))?;

        if store_bytes.is_empty() {
            if pdf.has_c2pa_manifest() {
                pdf.remove_manifest_bytes()
                    .map_err(|e| Error::InvalidAsset(e.to_string()))?;
            }
        } else if pdf.has_c2pa_manifest() {
            pdf.replace_manifest_bytes(store_bytes.to_vec())
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        } else {
            pdf.write_manifest_as_embedded_file(store_bytes.to_vec())
                .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        }

        let mut saved = Cursor::new(Vec::new());
        pdf.save_to(&mut saved)
            .map_err(|e| Error::InvalidAsset(e.to_string()))?;
        output_stream
            .write_all(&saved.into_inner())
            .map_err(Error::IoError)
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> crate::Result<Vec<HashObjectPositions>> {
        input_stream.rewind()?;

        let mut input_bytes = Vec::new();
        input_stream.read_to_end(&mut input_bytes)?;

        let (manifest_pos, manifest_len, file_end) = match self
            .locate_manifest_range_in_bytes(&input_bytes)?
        {
            Some((start, length)) => (start, length, input_bytes.len()),
            None => {
                let mut read_cursor = Cursor::new(input_bytes.clone());
                let mut pdf = Pdf::from_reader(&mut read_cursor)
                    .map_err(|e| Error::InvalidAsset(e.to_string()))?;

                // pre-sign placeholder path: synthesize where write_cai will place CAI
                if pdf.has_c2pa_manifest() {
                    pdf.remove_manifest_bytes()
                        .map_err(|e| Error::InvalidAsset(e.to_string()))?;
                }

                pdf.write_manifest_as_embedded_file(LOCATION_MARKER.to_vec())
                    .map_err(|e| Error::InvalidAsset(e.to_string()))?;

                let mut output_stream = Cursor::new(Vec::new());
                pdf.save_to(&mut output_stream)
                    .map_err(|e| Error::InvalidAsset(e.to_string()))?;
                let output_bytes = output_stream.into_inner();

                let pos = Self::find_unique_subslice(&output_bytes, LOCATION_MARKER)?;

                (pos, LOCATION_MARKER.len(), output_bytes.len())
            }
        };

        let marker_end = manifest_pos + manifest_len;

        Ok(vec![
            HashObjectPositions {
                offset: manifest_pos,
                length: manifest_len,
                htype: HashBlockObjectType::Cai,
            },
            HashObjectPositions {
                offset: 0,
                length: manifest_pos,
                htype: HashBlockObjectType::Other,
            },
            HashObjectPositions {
                offset: marker_end,
                length: file_end.saturating_sub(marker_end),
                htype: HashBlockObjectType::Other,
            },
        ])
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> crate::Result<()> {
        self.write_cai(input_stream, output_stream, &[])
    }
}

impl ComposedManifestRef for PdfIO {
    // Return entire CAI block as Vec<u8>
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>, Error> {
        Ok(manifest_data.to_vec())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PdfError {
    #[error("invalid file signature: {reason}")]
    InvalidFileSignature { reason: String },
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::io::Cursor;

    use crate::{
        asset_handlers,
        asset_handlers::{pdf::MockC2paPdf, pdf_io::PdfIO},
        asset_io::{AssetIO, CAIReader},
    };

    static MANIFEST_BYTES: &[u8; 2] = &[10u8, 20u8];

    #[test]
    fn test_error_reading_manifest_fails() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_manifest_bytes().returning(|| {
            Err(asset_handlers::pdf::Error::UnableToReadPdf(
                lopdf::Error::ReferenceLimit,
            ))
        });

        let pdf_io = PdfIO::new("pdf");
        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::PdfReadError)
        ))
    }

    #[test]
    fn test_no_manifest_found_returns_no_jumbf_error() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_manifest_bytes().returning(|| Ok(None));
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_one_manifest_found_returns_bytes() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf
            .expect_read_manifest_bytes()
            .returning(|| Ok(Some(vec![MANIFEST_BYTES])));

        let pdf_io = PdfIO::new("pdf");
        assert_eq!(
            pdf_io.read_manifest_bytes(mock_pdf).unwrap(),
            MANIFEST_BYTES.to_vec()
        );
    }

    #[test]
    fn test_multiple_manifest_fail_with_not_implemented_error() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf
            .expect_read_manifest_bytes()
            .returning(|| Ok(Some(vec![MANIFEST_BYTES, MANIFEST_BYTES, MANIFEST_BYTES])));

        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_manifest_bytes(mock_pdf),
            Err(crate::Error::NotImplemented(_))
        ));
    }

    #[test]
    fn test_returns_none_when_no_xmp() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_xmp().returning(|| None);

        let pdf_io = PdfIO::new("pdf");
        assert_eq!(pdf_io.read_xmp_from_pdf(mock_pdf), None);
    }

    #[test]
    fn test_returns_some_when_some_xmp() {
        let mut mock_pdf = MockC2paPdf::default();
        mock_pdf.expect_read_xmp().returning(|| Some("xmp".into()));

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp_from_pdf(mock_pdf).is_some());
    }

    #[test]
    fn test_cai_read_finds_no_manifest() {
        let source = crate::utils::test::fixture_path("basic.pdf");
        let pdf_io = PdfIO::new("pdf");

        assert!(matches!(
            pdf_io.read_cai_store(&source),
            Err(crate::Error::JumbfNotFound)
        ));
    }

    #[test]
    fn test_cai_read_xmp_finds_xmp_data() {
        let source = include_bytes!("../../tests/fixtures/basic.pdf");
        let mut stream = Cursor::new(source.to_vec());

        let pdf_io = PdfIO::new("pdf");
        assert!(pdf_io.read_xmp(&mut stream).is_some());
    }

    #[test]
    fn test_read_cai_express_pdf_finds_single_manifest_store() {
        let source = include_bytes!("../../tests/fixtures/express-signed.pdf");
        let pdf_io = PdfIO::new("pdf");
        let mut pdf_stream = Cursor::new(source.to_vec());
        assert!(pdf_io.read_cai(&mut pdf_stream).is_ok());
    }

    #[test]
    fn test_find_unique_subslice_returns_match_offset() {
        let index = PdfIO::find_unique_subslice(b"abc123xyz", b"123").unwrap();
        assert_eq!(index, 3);
    }

    #[test]
    fn test_find_unique_subslice_rejects_empty_needle() {
        let err = PdfIO::find_unique_subslice(b"abc", b"").unwrap_err();
        assert!(matches!(err, crate::Error::InvalidAsset(_)));
    }

    #[test]
    fn test_find_unique_subslice_rejects_ambiguous_matches() {
        let err = PdfIO::find_unique_subslice(b"abcabc", b"abc").unwrap_err();
        assert!(matches!(err, crate::Error::InvalidAsset(_)));
    }
}
