//! Shared greyscale QR decode for desktop and Android camera / file paths.

/// Soft ceiling shared with Android/desktop camera frames — refuse absurd dimensions early.
const MAX_LUMA_DIM: usize = 8_192;
const MAX_LUMA_PIXELS: usize = 16 * 1024 * 1024;

/// Decode the first QR in a greyscale buffer. Caller filters for Ghal Bol invites.
pub fn decode_luma(width: usize, height: usize, gray: &[u8]) -> Result<String, String> {
    if width == 0 || height == 0 || width > MAX_LUMA_DIM || height > MAX_LUMA_DIM {
        return Err("empty picture".into());
    }
    let Some(need) = width.checked_mul(height) else {
        return Err("empty picture".into());
    };
    if need > MAX_LUMA_PIXELS || gray.len() < need {
        return Err("empty picture".into());
    }
    let mut prepared = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        gray[y * width + x]
    });
    let grids = prepared.detect_grids();
    if grids.is_empty() {
        return Err("No QR code in that picture".into());
    }
    grids[0]
        .decode()
        .map(|(_meta, text)| text)
        .map_err(|e| format!("QR decode: {e}"))
}

/// Decode the first QR in an encoded PNG / JPEG picture.
#[cfg(target_os = "android")]
pub fn decode_image_bytes(bytes: &[u8]) -> Result<String, String> {
    // Picker already bounds file size; still reject absurd decoded dimensions.
    const MAX_QR_DECODE_PIXELS: u64 = 16 * 1024 * 1024;
    let img = image::load_from_memory(bytes)
        .map_err(|e| format!("could not open picture: {e}"))?
        .to_luma8();
    let pixels = u64::from(img.width()).saturating_mul(u64::from(img.height()));
    if pixels > MAX_QR_DECODE_PIXELS {
        return Err("picture resolution is too high to scan".into());
    }
    decode_luma(img.width() as usize, img.height() as usize, img.as_raw())
}

/// True when the payload is a Ghal Bol connect invite (ignore other QRs in view).
pub fn is_ghalbol_invite(text: &str) -> bool {
    crate::connect_invite_v1::parse_connect_invite_uri(text.trim()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect_invite_v1::{
        build_connect_invite_wire_map, connect_invite_app_uri_from_wire_map,
    };
    use crate::keystore_v1::create_keystore_v1;

    #[test]
    fn invite_detector_accepts_app_uri() {
        let (_ks, id) = create_keystore_v1("pw", None).unwrap();
        let wire = build_connect_invite_wire_map("ghalbol-chat", &id.public_key_hex(), None).unwrap();
        let uri = connect_invite_app_uri_from_wire_map(&wire).unwrap();
        assert!(is_ghalbol_invite(&uri));
        assert!(is_ghalbol_invite(&format!("  {uri}  ")));
    }

    #[test]
    fn invite_detector_rejects_noise() {
        assert!(!is_ghalbol_invite("https://example.com"));
        assert!(!is_ghalbol_invite("ghalbol://connect/"));
        assert!(!is_ghalbol_invite("not a qr"));
        assert!(!is_ghalbol_invite(""));
    }

    #[test]
    fn decode_luma_rejects_overflowing_and_oversize_dims() {
        assert!(decode_luma(0, 10, &[]).is_err());
        assert!(decode_luma(10, 0, &[]).is_err());
        assert!(decode_luma(MAX_LUMA_DIM + 1, 1, &[0u8; 16]).is_err());
        // usize::MAX/2 * 3 would overflow on 64-bit; checked_mul must reject.
        let err = decode_luma(usize::MAX / 2, 3, &[0u8; 8]).unwrap_err();
        assert!(err.contains("empty"), "{err}");
    }
}
