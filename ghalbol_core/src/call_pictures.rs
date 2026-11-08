//! Call video pictures for the UI: the latest local and remote frames as RGBA tiles.
//! Desktop and Android share this; capture and decode live in `call_video`.

use std::sync::Mutex;

struct Pictures {
    local_gen: u64,
    remote_gen: u64,
}

fn pictures() -> &'static Mutex<Pictures> {
    static P: std::sync::OnceLock<Mutex<Pictures>> = std::sync::OnceLock::new();
    P.get_or_init(|| {
        Mutex::new(Pictures {
            local_gen: 0,
            remote_gen: 0,
        })
    })
}

/// Latest local / remote frames as RGBA (downscaled), or empty when that side has no new frame.
pub fn call_picture_rgbas(
    call_id: &str,
) -> (Option<(u32, u32, Vec<u8>)>, Option<(u32, u32, Vec<u8>)>) {
    let mut slot = match pictures().lock() {
        Ok(g) => g,
        Err(_) => return (None, None),
    };
    let mut local_out = None;
    let mut remote_out = None;
    if let Some((frame, frame_gen)) =
        crate::call_video::latest_local_preview(call_id, slot.local_gen)
    {
        slot.local_gen = frame_gen;
        let rgba = crate::call_video::i420_to_rgba(&frame);
        let (rgba, w, h) = downscale(&rgba, frame.width, frame.height, 320);
        local_out = Some((w, h, rgba));
    }
    if let Some((frame, frame_gen)) =
        crate::call_video::latest_decoded_frame(call_id, slot.remote_gen)
    {
        slot.remote_gen = frame_gen;
        let rgba = crate::call_video::i420_to_rgba(&frame);
        let (rgba, w, h) = downscale(&rgba, frame.width, frame.height, 640);
        remote_out = Some((w, h, rgba));
    }
    (local_out, remote_out)
}

pub fn clear_call_pictures() {
    if let Ok(mut slot) = pictures().lock() {
        *slot = Pictures {
            local_gen: 0,
            remote_gen: 0,
        };
    }
}

/// Match call_video I420 convert ceilings — refuse pathological tiles before allocate.
const MAX_PICTURE_DIM: u32 = 4_096;
const MAX_PICTURE_PIXELS: u64 = 8 * 1024 * 1024;

fn downscale(src: &[u8], width: u32, height: u32, max_w: u32) -> (Vec<u8>, u32, u32) {
    if width == 0
        || height == 0
        || width > MAX_PICTURE_DIM
        || height > MAX_PICTURE_DIM
        || (u64::from(width) * u64::from(height)) > MAX_PICTURE_PIXELS
    {
        return (Vec::new(), 0, 0);
    }
    if width <= max_w {
        return (src.to_vec(), width, height);
    }
    let dst_w = max_w;
    let dst_h = ((height as u64 * dst_w as u64) / width as u64).max(1) as u32;
    let mut dst = vec![0u8; (dst_w as usize) * (dst_h as usize) * 4];
    for y in 0..dst_h {
        let sy = (y as u64 * height as u64 / dst_h as u64) as u32;
        for x in 0..dst_w {
            let sx = (x as u64 * width as u64 / dst_w as u64) as u32;
            let si = ((sy as usize) * (width as usize) + sx as usize) * 4;
            let di = ((y as usize) * (dst_w as usize) + x as usize) * 4;
            if si + 3 < src.len() {
                dst[di..di + 4].copy_from_slice(&src[si..si + 4]);
            }
        }
    }
    (dst, dst_w, dst_h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downscale_rejects_pathological_dimensions() {
        let (rgba, w, h) = downscale(&[0u8; 4], MAX_PICTURE_DIM + 1, 64, 320);
        assert!(rgba.is_empty());
        assert_eq!((w, h), (0, 0));
        let (rgba2, w2, h2) = downscale(&[0u8; 4], 4096, 4096, 320);
        assert!(rgba2.is_empty());
        assert_eq!((w2, h2), (0, 0));
    }

    #[test]
    fn downscale_passthrough_small_tile() {
        let src = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let (rgba, w, h) = downscale(&src, 2, 1, 320);
        assert_eq!((w, h), (2, 1));
        assert_eq!(rgba, src);
    }
}
