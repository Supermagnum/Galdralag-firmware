//! Decode QR codes from image files (OpenPGP key material in payload).

use galdra_core_host::GaldraError;
use std::path::Path;

/// Read the first decoded QR payload from an image (PNG, JPEG, etc.).
pub fn decode_qr_image(path: &Path) -> Result<Vec<u8>, GaldraError> {
    let img =
        image::open(path).map_err(|e| GaldraError::Config(format!("cannot open image: {e}")))?;
    let luma = img.to_luma8();
    let mut prepared = rqrr::PreparedImage::prepare(luma);
    let grids = prepared.detect_grids();
    let grid = grids
        .into_iter()
        .next()
        .ok_or_else(|| GaldraError::Config("no QR code found in image".to_string()))?;
    let (_meta, content) = grid
        .decode()
        .map_err(|e| GaldraError::Config(format!("QR decode failed: {e}")))?;
    Ok(content.into_bytes())
}
