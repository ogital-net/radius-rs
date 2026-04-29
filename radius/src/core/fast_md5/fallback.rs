use super::K;

// ─────────────────────────────────────────────────────────────────────────────
// Portable fallback (all other architectures)
// ─────────────────────────────────────────────────────────────────────────────

// Always compiled on every platform so it can be compared against the
// arch-specific implementations in tests (see fast_md5/mod.rs `tests`).
#[allow(dead_code)]
#[allow(clippy::too_many_lines)] // intentionally monolithic for LLVM; not worth splitting
#[allow(clippy::many_single_char_names)] // a/b/c/d/m are standard MD5 register names
#[allow(clippy::cast_ptr_alignment)] // read_unaligned() is used immediately after the cast
#[inline]
pub(crate) fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let m = block.as_ptr().cast::<u32>();

    let load = |i: usize| -> u32 {
        // SAFETY: block is 64 bytes, i in 0..16
        u32::from_le(unsafe { m.add(i).read_unaligned() })
    };

    let (a0, b0, c0, d0) = (state[0], state[1], state[2], state[3]);
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

    macro_rules! step {
        (F, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add($d ^ ($b & ($c ^ $d)))
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
        // G with delayed-B trick: split into (~D & C) + (D & B)
        (G, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add((!$d & $c).wrapping_add($d & $b))
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
        (H, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add($b ^ $c ^ $d)
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
        (I, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add($c ^ ($b | !$d))
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
    }

    step!(F, a, b, c, d, 0, K[0], 7);
    step!(F, d, a, b, c, 1, K[1], 12);
    step!(F, c, d, a, b, 2, K[2], 17);
    step!(F, b, c, d, a, 3, K[3], 22);
    step!(F, a, b, c, d, 4, K[4], 7);
    step!(F, d, a, b, c, 5, K[5], 12);
    step!(F, c, d, a, b, 6, K[6], 17);
    step!(F, b, c, d, a, 7, K[7], 22);
    step!(F, a, b, c, d, 8, K[8], 7);
    step!(F, d, a, b, c, 9, K[9], 12);
    step!(F, c, d, a, b, 10, K[10], 17);
    step!(F, b, c, d, a, 11, K[11], 22);
    step!(F, a, b, c, d, 12, K[12], 7);
    step!(F, d, a, b, c, 13, K[13], 12);
    step!(F, c, d, a, b, 14, K[14], 17);
    step!(F, b, c, d, a, 15, K[15], 22);

    step!(G, a, b, c, d, 1, K[16], 5);
    step!(G, d, a, b, c, 6, K[17], 9);
    step!(G, c, d, a, b, 11, K[18], 14);
    step!(G, b, c, d, a, 0, K[19], 20);
    step!(G, a, b, c, d, 5, K[20], 5);
    step!(G, d, a, b, c, 10, K[21], 9);
    step!(G, c, d, a, b, 15, K[22], 14);
    step!(G, b, c, d, a, 4, K[23], 20);
    step!(G, a, b, c, d, 9, K[24], 5);
    step!(G, d, a, b, c, 14, K[25], 9);
    step!(G, c, d, a, b, 3, K[26], 14);
    step!(G, b, c, d, a, 8, K[27], 20);
    step!(G, a, b, c, d, 13, K[28], 5);
    step!(G, d, a, b, c, 2, K[29], 9);
    step!(G, c, d, a, b, 7, K[30], 14);
    step!(G, b, c, d, a, 12, K[31], 20);

    step!(H, a, b, c, d, 5, K[32], 4);
    step!(H, d, a, b, c, 8, K[33], 11);
    step!(H, c, d, a, b, 11, K[34], 16);
    step!(H, b, c, d, a, 14, K[35], 23);
    step!(H, a, b, c, d, 1, K[36], 4);
    step!(H, d, a, b, c, 4, K[37], 11);
    step!(H, c, d, a, b, 7, K[38], 16);
    step!(H, b, c, d, a, 10, K[39], 23);
    step!(H, a, b, c, d, 13, K[40], 4);
    step!(H, d, a, b, c, 0, K[41], 11);
    step!(H, c, d, a, b, 3, K[42], 16);
    step!(H, b, c, d, a, 6, K[43], 23);
    step!(H, a, b, c, d, 9, K[44], 4);
    step!(H, d, a, b, c, 12, K[45], 11);
    step!(H, c, d, a, b, 15, K[46], 16);
    step!(H, b, c, d, a, 2, K[47], 23);

    step!(I, a, b, c, d, 0, K[48], 6);
    step!(I, d, a, b, c, 7, K[49], 10);
    step!(I, c, d, a, b, 14, K[50], 15);
    step!(I, b, c, d, a, 5, K[51], 21);
    step!(I, a, b, c, d, 12, K[52], 6);
    step!(I, d, a, b, c, 3, K[53], 10);
    step!(I, c, d, a, b, 10, K[54], 15);
    step!(I, b, c, d, a, 1, K[55], 21);
    step!(I, a, b, c, d, 8, K[56], 6);
    step!(I, d, a, b, c, 15, K[57], 10);
    step!(I, c, d, a, b, 6, K[58], 15);
    step!(I, b, c, d, a, 13, K[59], 21);
    step!(I, a, b, c, d, 4, K[60], 6);
    step!(I, d, a, b, c, 11, K[61], 10);
    step!(I, c, d, a, b, 2, K[62], 15);
    step!(I, b, c, d, a, 9, K[63], 21);

    state[0] = a0.wrapping_add(a);
    state[1] = b0.wrapping_add(b);
    state[2] = c0.wrapping_add(c);
    state[3] = d0.wrapping_add(d);
}
