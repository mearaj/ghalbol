//! Length-prefixed channel mux inside a Noise transport session.

pub const MUX_HEADER_LEN: usize = 8;
/// Max mux payload after Noise decrypt (Noise transport messages are ≤ 65535).
pub const MAX_MUX_PAYLOAD: usize = 65_535 - MUX_HEADER_LEN;
pub const CHANNEL_MSG: u32 = 0;
pub const CHANNEL_CALL_AUDIO: u32 = 1;
pub const CHANNEL_CALL_VIDEO: u32 = 2;
pub const CHANNEL_ATTACH: u32 = 3;
pub const CHANNEL_KEEPALIVE: u32 = 0xFFFF_FFFF;

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_mux_plaintext(plaintext: &[u8]) -> Result<(u32, Vec<u8>), &'static str> {
        if plaintext.len() < MUX_HEADER_LEN {
            return Err("short");
        }
        let channel = u32::from_be_bytes(plaintext[0..4].try_into().unwrap());
        let len = u32::from_be_bytes(plaintext[4..8].try_into().unwrap()) as usize;
        if len > MAX_MUX_PAYLOAD {
            return Err("oversize");
        }
        if plaintext.len() != MUX_HEADER_LEN + len {
            return Err("length mismatch");
        }
        Ok((channel, plaintext[MUX_HEADER_LEN..].to_vec()))
    }

    fn encode_mux_plaintext(channel: u32, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        if payload.len() > MAX_MUX_PAYLOAD {
            return Err("oversize");
        }
        let mut out = Vec::with_capacity(MUX_HEADER_LEN + payload.len());
        out.extend_from_slice(&channel.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    #[test]
    fn max_mux_payload_fits_noise_frame() {
        assert_eq!(MAX_MUX_PAYLOAD + MUX_HEADER_LEN, 65_535);
    }

    #[test]
    fn mux_roundtrip_and_rejects_length_mismatch() {
        let wire = encode_mux_plaintext(CHANNEL_MSG, b"hi").unwrap();
        let (ch, body) = parse_mux_plaintext(&wire).unwrap();
        assert_eq!(ch, CHANNEL_MSG);
        assert_eq!(body, b"hi");

        let mut padded = wire.clone();
        padded.push(0xff);
        assert!(parse_mux_plaintext(&padded).is_err());

        let mut short = wire.clone();
        short.pop();
        assert!(parse_mux_plaintext(&short).is_err());
    }
}
