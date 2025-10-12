extern crate alloc;
use alloc::vec;

use crate::belt::Belt;
use crate::poly::Poly;

#[inline(always)]
pub fn bpadd_in_place(a: &mut [Belt], b: &[Belt]) {
    assert!(a.len() >= b.len());

    for (a_belt, b_belt) in a
        .iter_mut()
        .zip(b.iter().map(Some).chain(core::iter::repeat(None)))
    {
        if let Some(b_belt) = b_belt {
            *a_belt = *b_belt + *a_belt;
        } else {
            break;
        }
    }
}

#[inline(always)]
pub fn bpsub(a: &[Belt], b: &[Belt], res: &mut [Belt]) {
    let a_len = a.len();
    let b_len = b.len();

    let res_len = core::cmp::max(a_len, b_len);

    for i in 0..res_len {
        let n = i;
        if i < a_len && i < b_len {
            res[n] = a[n] - b[n];
        } else if i < a_len {
            res[n] = a[n];
        } else {
            res[n] = -b[n];
        }
    }
}

#[inline(always)]
pub fn bpmul(a: &[Belt], b: &[Belt], res: &mut [Belt]) {
    if a.is_zero() || b.is_zero() {
        res.fill(Belt(0));
        return;
    }

    res.fill(Belt(0));

    let a_len = a.len();
    let b_len = b.len();

    for i in 0..a_len {
        if a[i] == 0 {
            continue;
        }
        for j in 0..b_len {
            res[i + j] = res[i + j] + a[i] * b[j];
        }
    }
}

#[inline(always)]
pub fn bpscal(scalar: Belt, b: &[Belt], res: &mut [Belt]) {
    for (res, bp) in res.iter_mut().zip(b.iter()) {
        *res = scalar * *bp;
    }
}

#[inline(always)]
pub fn bpdvr(a: &[Belt], b: &[Belt], q: &mut [Belt], res: &mut [Belt]) {
    if a.is_zero() {
        q.fill(Belt(0));
        res.fill(Belt(0));
        return;
    } else if b.is_zero() {
        panic!("divide by zero\r");
    };

    q.fill(Belt(0));
    res.fill(Belt(0));

    let a_end = a.degree() as usize;
    let mut r = a[0..(a_end + 1)].to_vec();

    let deg_b = b.degree();

    let mut i = a_end;
    let end_b = deg_b as usize;
    let mut deg_r = a.degree();
    let mut q_index = deg_r.saturating_sub(deg_b);

    while deg_r >= deg_b {
        let coeff = r[i] / b[end_b];
        q[q_index as usize] = coeff;
        for k in 0..(deg_b + 1) {
            let index = k as usize;
            if k <= a_end as u32 && k < b.len() as u32 && k <= (i as u32) {
                r[i - index] = r[i - index] - coeff * b[end_b - index];
            }
        }
        deg_r = deg_r.saturating_sub(1);
        q_index = q_index.saturating_sub(1);
        if deg_r == 0 && r[0] == 0 {
            break;
        }
        i -= 1;
    }

    let r_len = deg_r + 1;
    res[0..(r_len as usize)].copy_from_slice(&r[0..(r_len as usize)]);
}

/// Extended Euclidean Algorithm, GCD
#[inline(always)]
pub fn bpegcd(a: &[Belt], b: &[Belt], d: &mut [Belt], u: &mut [Belt], v: &mut [Belt]) {
    let mut m1_u = vec![Belt(0)];
    let mut m2_u = vec![Belt(1)];
    let mut m1_v = vec![Belt(1)];
    let mut m2_v = vec![Belt(0)];

    d.fill(Belt(0));
    u.fill(Belt(0));
    v.fill(Belt(0));

    let mut a = a.to_vec();
    let mut b = b.to_vec();

    while !b.is_zero() {
        let deg_a = a.degree();
        let deg_b = b.degree();
        let deg_q = deg_a.saturating_sub(deg_b);
        let len_q = deg_q + 1;
        let len_r = deg_b + 1;

        let mut q = vec![Belt(0); len_q as usize];
        let mut r = vec![Belt(0); len_r as usize];

        bpdvr(
            a.as_slice(),
            b.as_slice(),
            q.as_mut_slice(),
            r.as_mut_slice(),
        );

        a = b;
        b = r;

        let q_len = q.len();
        let m1_u_len = m1_u.len() as usize;

        let mut res1_len = q_len + m1_u_len - 1;
        let mut res1 = vec![Belt(0); res1_len as usize];
        bpmul(q.as_slice(), m1_u.as_slice(), res1.as_mut_slice());

        let m2_u_len = m2_u.len();

        let len_res2 = core::cmp::max(m2_u_len, res1_len);
        let mut res2 = vec![Belt(0); len_res2 as usize];
        bpsub(m2_u.as_slice(), res1.as_slice(), res2.as_mut_slice());

        m2_u = m1_u;
        m1_u = res2;

        let m1_v_len = m1_v.len() as usize;

        res1.fill(Belt(0));
        res1_len = q_len + m1_v_len - 1;

        bpmul(q.as_slice(), m1_v.as_slice(), res1.as_mut_slice());

        let m2_v_len = m2_v.len();

        let len_res3 = core::cmp::max(m2_v_len, res1_len);
        let mut res3 = vec![Belt(0); len_res3 as usize];

        bpsub(m2_v.as_slice(), res1.as_slice(), res3.as_mut_slice());

        m2_v = m1_v;
        m1_v = res3;
    }

    let a_len = a.len();
    d[0..a_len].copy_from_slice(&a[0..a_len]);

    let m2_u_len = m2_u.len();
    let m2_v_len = m2_v.len();

    u[0..(m2_u_len as usize)].copy_from_slice(&m2_u[0..(m2_u_len as usize)]);
    v[0..(m2_v_len as usize)].copy_from_slice(&m2_v[0..(m2_v_len as usize)]);
}
