use super::*;
use crate::{
    based,
    belt::{montify, Belt},
};

// assert that input is made of base field elements
pub fn assert_all_based(vecbelt: &[Belt]) {
    vecbelt.iter().for_each(|b| based!(b.0));
}

// calc q and r for vecbelt, based on RATE
pub fn tip5_calc_q_r(input_vec: &[Belt]) -> (usize, usize) {
    let lent_input = input_vec.len();
    let (q, r) = (lent_input / RATE, lent_input % RATE);
    (q, r)
}

// monitify vecbelt (bring into montgomery space)
pub fn tip5_montify_vecbelt(input_vec: &mut [Belt]) {
    for item in input_vec {
        item.0 = montify(item.0);
    }
}

// calc digest
pub fn tip5_calc_digest(sponge: &[u64; 16]) -> [u64; 5] {
    let mut digest = [0; 5];
    for i in 0..5 {
        digest[i] = mont_reduction(sponge[i] as u128);
    }
    digest
}

pub fn create_init_sponge_variable() -> [u64; STATE_SIZE] {
    [0u64; STATE_SIZE]
}

pub fn create_init_sponge_fixed() -> [u64; STATE_SIZE] {
    let mut sponge = [0u64; STATE_SIZE];
    for item in sponge.iter_mut().take(STATE_SIZE).skip(10) {
        *item = 4294967295u64;
    }
    sponge
}

pub fn tip5_absorb_sponge<const PAD: bool>(sponge: &mut [u64; STATE_SIZE], input: &[Belt]) {
    // |=  input=(list belt)
    // ^+  +>.$
    // =*  rng  +>.$

    // |^
    // ::  assert that input is made of base field elements
    // ?>  (levy input based)

    // =/  [q=@ r=@]  (dvr (lent input) rate)
    let l = input.len();
    let r = l % RATE;

    // ::  pad input with ~[1 0 ... 0] to be a multiple of rate
    // =.  input  (weld input [1 (reap (dec (sub rate r)) 0)])
    // ::  bring input into montgomery space
    // =.  input  (turn input montify)
    let (input, end) = input.as_chunks::<RATE>();
    let input = input.iter().copied().chain(if PAD {
        let mut r = [Belt(0); RATE];
        let (a, b) = r.split_at_mut(end.len());
        a.copy_from_slice(end);
        let (a, b) = b.split_at_mut(1);
        a[0] = Belt(1);
        b.iter_mut().for_each(|v| *v = Belt(0));
        Some(r)
    } else {
        debug_assert_eq!(r, 0);
        None
    });

    // |-
    // ?:  =(q 0)
    //   rng
    for mut input_head in input {
        tip5_montify_vecbelt(&mut input_head);
        let input_head = input_head.map(|b| b.0);

        // =.  sponge  (absorb-rate (scag rate input))

        // ++  absorb-rate
        //   ?>  =((lent input) rate)
        //   =.  sponge  (weld input (slag rate sponge))
        sponge[..RATE].copy_from_slice(&input_head);
        //   $:permute
        permute(sponge);
    }
}

pub fn hash_varlen(input_vec: &[Belt]) -> [u64; 5] {
    let mut sponge = create_init_sponge_variable();

    // assert that input is made of base field elements
    assert_all_based(input_vec);

    tip5_absorb_sponge::<true>(&mut sponge, input_vec);

    // calc digest
    tip5_calc_digest(&sponge)
}

pub fn hash_fixed(input_vec: &mut [Belt]) -> [u64; 5] {
    let mut sponge = create_init_sponge_variable();

    // assert that input is made of base field elements
    assert_all_based(input_vec);

    tip5_absorb_sponge::<false>(&mut sponge, input_vec);

    // calc digest
    tip5_calc_digest(&sponge)
}
