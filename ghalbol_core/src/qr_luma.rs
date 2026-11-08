//! Shared greyscale QR decode for desktop and Android camera / file paths.

/// Decode the first QR in a greyscale buffer. Caller filters for Ghal Bol invites.
pub fn decode_luma(width: usize, height: usize, gray: &[u8]) -> Result<String, String> {
    if width == 0 || height == 0 || gray.len() < width * height {
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
    let img = image::load_from_memory(bytes)
        .map_err(|e| format!("could not open picture: {e}"))?
        .to_luma8();
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
}
