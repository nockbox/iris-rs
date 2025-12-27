extern crate alloc;
use alloc::vec::Vec;

use bs58;
use crypto_bigint::{MulMod, U256};

use crate::belt::{bneg, Belt};
use crate::belt::{bpegcd, bpscal};

// Pre-computed constants stored as big-endian byte arrays
pub const G_ORDER: U256 = U256::from_be_slice(&[
    0x7a, 0xf2, 0x59, 0x9b, 0x3b, 0x3f, 0x22, 0xd0, 0x56, 0x3f, 0xbf, 0x0f, 0x99, 0x0a, 0x37, 0xb5,
    0x32, 0x7a, 0xa7, 0x23, 0x30, 0x15, 0x77, 0x22, 0xd4, 0x43, 0x62, 0x3e, 0xae, 0xd4, 0xac, 0xcf,
]);

pub const P_BIG: U256 = U256::from_be_slice(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
]);

pub const P_BIG_2: U256 = U256::from_be_slice(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x01,
]);

pub const P_BIG_3: U256 = U256::from_be_slice(&[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x05,
    0xff, 0xff, 0xff, 0xf9, 0x00, 0x00, 0x00, 0x05, 0xff, 0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x01,
]);

pub const A_GEN: CheetahPoint = CheetahPoint {
    x: F6lt([
        Belt(2754611494552410273),
        Belt(8599518745794843693),
        Belt(10526511002404673680),
        Belt(4830863958577994148),
        Belt(375185138577093320),
        Belt(12938930721685970739),
    ]),
    y: F6lt([
        Belt(15384029202802550068),
        Belt(2774812795997841935),
        Belt(14375303400746062753),
        Belt(10708493419890101954),
        Belt(13187678623570541764),
        Belt(9990732138772505951),
    ]),
    inf: false,
};

#[derive(Debug)]
pub enum CheetahError {
    Base58(bs58::decode::Error),
    InvalidLength(usize),
    ArrayConversion,
    NotOnCurve,
    DivisionByZero,
}

impl From<bs58::decode::Error> for CheetahError {
    fn from(e: bs58::decode::Error) -> Self {
        CheetahError::Base58(e)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheetahPoint {
    pub x: F6lt,
    pub y: F6lt,
    pub inf: bool,
}

impl CheetahPoint {
    pub fn into_base58(&self) -> Result<alloc::string::String, CheetahError> {
        if self.inf {
            return Err(CheetahError::NotOnCurve);
        }
        let mut bytes = Vec::new();
        bytes.push(0x1);
        for belt in self.y.0.iter().rev().chain(self.x.0.iter().rev()) {
            bytes.extend_from_slice(&belt.0.to_be_bytes());
        }
        Ok(bs58::encode(bytes).into_string())
    }

    pub fn from_base58(b58: &str) -> Result<Self, CheetahError> {
        let v = bs58::decode(b58).into_vec()?;

        if v.len() != 97 {
            return Err(CheetahError::InvalidLength(v.len()));
        }

        let mut v64 = v[1..]
            .chunks_exact(8)
            .map(|a| {
                let arr = <[u8; 8]>::try_from(a).map_err(|_| CheetahError::ArrayConversion)?;
                Ok(Belt(u64::from_be_bytes(arr)))
            })
            .collect::<Result<Vec<Belt>, CheetahError>>()?;

        v64.reverse();

        let c_pt = CheetahPoint {
            x: F6lt(<[Belt; 6]>::try_from(&v64[..6]).map_err(|_| CheetahError::ArrayConversion)?),
            y: F6lt(<[Belt; 6]>::try_from(&v64[6..]).map_err(|_| CheetahError::ArrayConversion)?),
            inf: false,
        };

        if c_pt.in_curve() {
            Ok(c_pt)
        } else {
            Err(CheetahError::NotOnCurve)
        }
    }

    pub fn in_curve(&self) -> bool {
        if *self == A_ID {
            return true;
        }
        let scaled = ch_scal_big(&G_ORDER, self).unwrap();
        scaled == A_ID
    }

    pub fn identity() -> Self {
        A_ID
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct F6lt(pub [Belt; 6]);

#[inline(always)]
pub fn f6_div(f1: &F6lt, f2: &F6lt) -> Result<F6lt, CheetahError> {
    let f2_inv = f6_inv(f2)?;
    Ok(f6_mul(f1, &f2_inv))
}

#[inline(always)]
fn karat3(a: &[Belt; 3], b: &[Belt; 3]) -> [Belt; 5] {
    let m = [a[0] * b[0], a[1] * b[1], a[2] * b[2]];
    [
        m[0],
        (a[0] + a[1]) * (b[0] + b[1]) - (m[0] + m[1]),
        (a[0] + a[2]) * (b[0] + b[2]) - (m[0] + m[2]) + m[1],
        (a[1] + a[2]) * (b[1] + b[2]) - (m[1] + m[2]),
        m[2],
    ]
}

#[inline(always)]
pub fn f6_mul(f: &F6lt, g: &F6lt) -> F6lt {
    let f0g0 = karat3(&[f.0[0], f.0[1], f.0[2]], &[g.0[0], g.0[1], g.0[2]]);
    let f1g1 = karat3(&[f.0[3], f.0[4], f.0[5]], &[g.0[3], g.0[4], g.0[5]]);

    let foil = karat3(
        &[f.0[0] + f.0[3], f.0[1] + f.0[4], f.0[2] + f.0[5]],
        &[g.0[0] + g.0[3], g.0[1] + g.0[4], g.0[2] + g.0[5]],
    );

    let cross = [
        foil[0] - (f0g0[0] + f1g1[0]),
        foil[1] - (f0g0[1] + f1g1[1]),
        foil[2] - (f0g0[2] + f1g1[2]),
        foil[3] - (f0g0[3] + f1g1[3]),
        foil[4] - (f0g0[4] + f1g1[4]),
    ];
    F6lt([
        f0g0[0] + Belt(7) * (cross[3] + f1g1[0]),
        f0g0[1] + Belt(7) * (cross[4] + f1g1[1]),
        f0g0[2] + Belt(7) * f1g1[2],
        f0g0[3] + cross[0] + Belt(7) * f1g1[3],
        f0g0[4] + cross[1] + Belt(7) * f1g1[4],
        cross[2],
    ])
}

#[inline(always)]
pub fn f6_inv(f: &F6lt) -> Result<F6lt, CheetahError> {
    if f == &F6_ZERO {
        return Err(CheetahError::DivisionByZero);
    }
    let mut res = [Belt(0); 6];
    let mut d = [Belt(0); 7];
    let mut u = [Belt(0); 7];
    let mut v = [Belt(0); 6];
    bpegcd(
        &f.0,
        &[
            Belt(bneg(7)),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(0),
            Belt(1),
        ],
        &mut d,
        &mut u,
        &mut v,
    );
    let inv = d[0].inv();
    bpscal(inv, &u, &mut res);
    Ok(F6lt(res))
}

#[inline(always)]
fn f6_add(f1: &F6lt, f2: &F6lt) -> F6lt {
    F6lt([
        f1.0[0] + f2.0[0],
        f1.0[1] + f2.0[1],
        f1.0[2] + f2.0[2],
        f1.0[3] + f2.0[3],
        f1.0[4] + f2.0[4],
        f1.0[5] + f2.0[5],
    ])
}

fn f6_scal(s: Belt, f: &F6lt) -> F6lt {
    F6lt([
        f.0[0] * s,
        f.0[1] * s,
        f.0[2] * s,
        f.0[3] * s,
        f.0[4] * s,
        f.0[5] * s,
    ])
}

#[inline(always)]
fn f6_square(f: &F6lt) -> F6lt {
    f6_mul(f, f)
}

#[inline(always)]
fn f6_neg(f: &F6lt) -> F6lt {
    F6lt([-f.0[0], -f.0[1], -f.0[2], -f.0[3], -f.0[4], -f.0[5]])
}

#[inline(always)]
fn f6_sub(f1: &F6lt, f2: &F6lt) -> F6lt {
    f6_add(f1, &f6_neg(f2))
}

#[inline(always)]
pub fn ch_double_unsafe(x: &F6lt, y: &F6lt) -> Result<CheetahPoint, CheetahError> {
    let slope = f6_div(
        &f6_add(&f6_scal(Belt(3), &f6_square(x)), &F6_ONE),
        &f6_scal(Belt(2), y),
    )?;
    let x_out = f6_sub(&f6_square(&slope), &f6_scal(Belt(2), x));
    let y_out = f6_sub(&f6_mul(&slope, &f6_sub(x, &x_out)), y);
    Ok(CheetahPoint {
        x: x_out,
        y: y_out,
        inf: false,
    })
}

pub const A_ID: CheetahPoint = CheetahPoint {
    x: F6_ZERO,
    y: F6_ONE,
    inf: true,
};
pub const F6_ZERO: F6lt = F6lt([Belt(0); 6]);
pub const F6_ONE: F6lt = F6lt([Belt(1), Belt(0), Belt(0), Belt(0), Belt(0), Belt(0)]);

#[inline(always)]
pub fn ch_double(p: CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    if p.inf {
        return Ok(A_ID);
    }
    if p.y == F6_ZERO {
        return Ok(A_ID);
    }
    ch_double_unsafe(&p.x, &p.y)
}

#[inline(always)]
pub fn ch_add_unsafe(p: CheetahPoint, q: CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let slope = f6_div(&f6_sub(&p.y, &q.y), &f6_sub(&p.x, &q.x))?;
    let x_out = f6_sub(&f6_square(&slope), &f6_add(&p.x, &q.x));
    let y_out = f6_sub(&f6_mul(&slope, &f6_sub(&p.x, &x_out)), &p.y);
    Ok(CheetahPoint {
        x: x_out,
        y: y_out,
        inf: false,
    })
}

#[inline(always)]
pub fn ch_neg(p: &CheetahPoint) -> CheetahPoint {
    CheetahPoint {
        x: p.x,
        y: f6_neg(&p.y),
        inf: p.inf,
    }
}

#[inline(always)]
pub fn ch_add(p: &CheetahPoint, q: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    if p.inf {
        return Ok(*q);
    }
    if q.inf {
        return Ok(*p);
    }
    if *p == ch_neg(q) {
        return Ok(A_ID);
    }
    if p == q {
        return ch_double(*p);
    }
    ch_add_unsafe(*p, *q)
}

#[inline(always)]
pub fn ch_scal(n: u64, p: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    let mut n = n;
    let mut p_copy = *p;
    let mut acc = A_ID;
    while n > 0 {
        if n & 1 == 1 {
            acc = ch_add(&acc, &p_copy)?;
        }
        p_copy = ch_double(p_copy)?;
        n >>= 1;
    }
    Ok(acc)
}

#[inline(always)]
pub fn ch_scal_big(n: &U256, p: &CheetahPoint) -> Result<CheetahPoint, CheetahError> {
    if *n == U256::ZERO {
        return Ok(A_ID);
    }
    let mut acc = A_ID;
    for byte in n.to_be_bytes() {
        for bit in (0..8).rev() {
            acc = ch_double(acc)?;
            if (byte >> bit) & 1 == 1 {
                acc = ch_add(&acc, p)?;
            }
        }
    }
    Ok(acc)
}

pub fn trunc_g_order(a: &[u64]) -> U256 {
    let mut result = U256::from_u64(a[0]);

    let term1 = MulMod::mul_mod(&P_BIG, &U256::from_u64(a[1]), &G_ORDER);
    result = result.add_mod(&term1, &G_ORDER);

    let term2 = MulMod::mul_mod(&P_BIG_2, &U256::from_u64(a[2]), &G_ORDER);
    result = result.add_mod(&term2, &G_ORDER);

    let term3 = MulMod::mul_mod(&P_BIG_3, &U256::from_u64(a[3]), &G_ORDER);
    result.add_mod(&term3, &G_ORDER)
}
