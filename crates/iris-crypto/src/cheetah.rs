use arrayvec::ArrayVec;
use iris_ztd::{
    crypto::cheetah::{
        ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahPoint, F6lt, A_GEN, G_ORDER,
    },
    tip5::hash::hash_varlen,
    Belt, Digest, Hashable, MulMod, U256,
};
#[cfg(feature = "alloc")]
use iris_ztd::{Noun, NounDecode, NounEncode};
#[cfg(feature = "alloc")]
use alloc::{boxed::Box, format, string::ToString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "alloc", derive(NounEncode, NounDecode))]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct PublicKey(pub CheetahPoint);

impl PublicKey {
    pub fn verify(&self, m: &Digest, sig: &Signature) -> bool {
        if sig.c == U256::ZERO || sig.c >= G_ORDER || sig.s == U256::ZERO || sig.s >= G_ORDER {
            return false;
        }

        // Compute scalar = s*G - c*pubkey
        // This is equivalent to: scalar = s*G + (-c)*pubkey
        let sg = match ch_scal_big(&sig.s, &A_GEN) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        let c_pk = match ch_scal_big(&sig.c, &self.0) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        let scalar = match ch_add(&sg, &ch_neg(&c_pk)) {
            Ok(pt) => pt,
            Err(_) => return false,
        };
        let chal = {
            let mut transcript: ArrayVec<Belt, { 6 + 6 + 6 + 6 + 5 }> = ArrayVec::new();
            transcript.try_extend_from_slice(&scalar.x.0).unwrap();
            transcript.try_extend_from_slice(&scalar.y.0).unwrap();
            transcript.try_extend_from_slice(&self.0.x.0).unwrap();
            transcript.try_extend_from_slice(&self.0.y.0).unwrap();
            transcript.try_extend_from_slice(&m.0).unwrap();
            trunc_g_order(&hash_varlen(&transcript))
        };

        chal == sig.c
    }

    pub fn to_be_bytes(&self) -> [u8; 97] {
        let mut data = [0u8; 97];
        data[0] = 0x01; // prefix byte
        let mut offset = 1;
        // y-coordinate: 6 belts × 8 bytes = 48 bytes
        for belt in self.0.y.0.iter().rev() {
            data[offset..offset + 8].copy_from_slice(&belt.0.to_be_bytes());
            offset += 8;
        }
        // x-coordinate: 6 belts × 8 bytes = 48 bytes
        for belt in self.0.x.0.iter().rev() {
            data[offset..offset + 8].copy_from_slice(&belt.0.to_be_bytes());
            offset += 8;
        }
        data
    }

    pub fn from_be_bytes(bytes: &[u8]) -> PublicKey {
        let mut x = [Belt(0); 6];
        let mut y = [Belt(0); 6];

        // y-coordinate: bytes 1-48
        for i in 0..6 {
            let offset = 1 + i * 8;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[offset..offset + 8]);
            y[5 - i] = Belt(u64::from_be_bytes(buf));
        }

        // x-coordinate: bytes 49-96
        for i in 0..6 {
            let offset = 49 + i * 8;
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[offset..offset + 8]);
            x[5 - i] = Belt(u64::from_be_bytes(buf));
        }

        PublicKey(CheetahPoint {
            x: F6lt(x),
            y: F6lt(y),
            inf: false,
        })
    }

    /// SLIP-10 compatible serialization (legacy 65-byte format for compatibility)
    pub(crate) fn as_slip10_bytes(&self) -> [u8; 96] {
        let mut data = [0u8; 96];
        let mut offset = 0;
        for belt in self.0.y.0.iter().rev().chain(self.0.x.0.iter().rev()) {
            data[offset..offset + 8].copy_from_slice(&belt.0.to_be_bytes());
            offset += 8;
        }
        data
    }
}

impl core::ops::Add for &PublicKey {
    type Output = PublicKey;

    fn add(self, other: &PublicKey) -> PublicKey {
        PublicKey(ch_add(&self.0, &other.0).unwrap())
    }
}

impl core::ops::Add for PublicKey {
    type Output = PublicKey;

    fn add(self, other: PublicKey) -> PublicKey {
        (&self as &PublicKey) + (&other as &PublicKey)
    }
}

impl core::ops::AddAssign for PublicKey {
    fn add_assign(&mut self, other: PublicKey) {
        *self = *self + other;
    }
}

impl core::ops::Sub for &PublicKey {
    type Output = PublicKey;

    fn sub(self, other: &PublicKey) -> PublicKey {
        PublicKey(ch_add(&self.0, &ch_neg(&other.0)).unwrap())
    }
}

impl core::ops::SubAssign for PublicKey {
    fn sub_assign(&mut self, other: PublicKey) {
        *self = &*self - &other;
    }
}

impl core::iter::Sum<PublicKey> for PublicKey {
    fn sum<I: Iterator<Item = PublicKey>>(iter: I) -> Self {
        iter.fold(PublicKey(CheetahPoint::identity()), |acc, x| acc + x)
    }
}

impl<'a> core::iter::Sum<&'a PublicKey> for PublicKey {
    fn sum<I: Iterator<Item = &'a PublicKey>>(iter: I) -> Self {
        iter.fold(PublicKey(CheetahPoint::identity()), |acc, x| &acc + x)
    }
}

impl Hashable for PublicKey {
    fn hash(&self) -> Digest {
        self.0.hash()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "wasm", tsify(into_wasm_abi, from_wasm_abi))]
pub struct Signature {
    pub c: U256, // challenge
    pub s: U256, // signature scalar
}

// Aggregate signature of the same challenge
impl core::iter::Sum<Signature> for Option<Signature> {
    fn sum<I: Iterator<Item = Signature>>(mut iter: I) -> Self {
        let mut c = None;
        let s = iter.try_fold(U256::ZERO, |acc, x| {
            if c.is_some() && c.as_ref() != Some(&x.c) {
                return None;
            }
            c = Some(x.c);
            Some(acc.add_mod(&x.s, &G_ORDER))
        });
        Some(Signature { c: c?, s: s? })
    }
}

#[cfg(feature = "alloc")]
impl NounEncode for Signature {
    fn to_noun(&self) -> Noun {
        (
            Belt::from_bytes(&self.c.to_le_bytes()).as_slice(),
            Belt::from_bytes(&self.s.to_le_bytes()).as_slice(),
        )
            .to_noun()
    }
}

#[cfg(feature = "alloc")]
impl NounDecode for Signature {
    fn from_noun(noun: &Noun) -> Option<Self> {
        let (c, s): ([Belt; 8], [Belt; 8]) = NounDecode::from_noun(noun)?;

        let c = Belt::to_bytes(&c);
        let s = Belt::to_bytes(&s);

        Some(Signature {
            c: U256::from_le_slice(&c),
            s: U256::from_le_slice(&s),
        })
    }
}

// TODO: unblock alloc-less signature hashing by implementing allocless Belt::from_bytes
#[cfg(feature = "alloc")]
impl Hashable for Signature {
    fn hash(&self) -> Digest {
        self.to_noun().hash()
    }
}

#[derive(Debug, Clone)]
pub struct PrivateKey(pub U256);

impl Drop for PrivateKey {
    fn drop(&mut self) {
        unsafe {
            core::ptr::write_volatile(&mut self.0, U256::ZERO);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey(ch_scal_big(&self.0, &A_GEN).unwrap())
    }

    pub fn sign(&self, m: &Digest) -> Signature {
        self.sign_multi(m, &self.nonce_for(m), &self.public_key())
    }

    pub fn nonce_for(&self, m: &Digest) -> U256 {
        let pubkey = self.public_key().0;
        let nonce = {
            let mut transcript: ArrayVec<Belt, { 6 + 6 + 5 + 8 }> = ArrayVec::new();
            transcript.try_extend_from_slice(&pubkey.x.0).unwrap();
            transcript.try_extend_from_slice(&pubkey.y.0).unwrap();
            transcript.try_extend_from_slice(&m.0).unwrap();
            self.0.to_le_bytes().chunks(4).for_each(|chunk| {
                let mut buf = [0u8; 4];
                buf[..chunk.len()].copy_from_slice(chunk);
                transcript.push(Belt(u32::from_le_bytes(buf) as u64));
            });
            trunc_g_order(&hash_varlen(&transcript))
        };
        nonce
    }

    pub fn combine_nonces(nonces: &[U256]) -> U256 {
        nonces
            .iter()
            .fold(U256::ZERO, |acc, x| acc.add_mod(x, &G_ORDER))
    }

    /// Perform a multiparty sign
    ///
    /// # Arguments
    /// * `m` - The digest of message to sign
    /// * `shared_nonce` - The challenge nonce. This is after taking `nonce_for(m)` on all private keys, and combining them with [`PrivateKey::combine_nonces`].
    /// * `combined_pubkey` - The combined public key to sign against.
    ///
    /// # Returns
    /// * `Signature` - The partial signature. This will be invalid until combined with other partial signatures.
    ///
    /// # Example
    ///
    /// ```
    /// # use iris_ztd::{Digest, Belt, U256};
    /// # use iris_crypto::cheetah::*;
    /// let pk1 = PrivateKey(U256::from_u64(123));
    /// let pk2 = PrivateKey(U256::from_u64(456));
    /// let m = Digest([Belt(8), Belt(9), Belt(10), Belt(11), Belt(12)]);
    /// let nonce1 = pk1.nonce_for(&m);
    /// let nonce2 = pk2.nonce_for(&m);
    /// let combined_nonce = PrivateKey::combine_nonces(&[nonce1, nonce2]);
    /// let combined_pubkey = pk1.public_key() + pk2.public_key();
    /// let sig1 = pk1.sign_multi(&m, &combined_nonce, &combined_pubkey);
    /// let sig2 = pk2.sign_multi(&m, &combined_nonce, &combined_pubkey);
    /// let sig = [sig1, sig2].into_iter().sum::<Option<Signature>>().unwrap();
    /// assert!(combined_pubkey.verify(&m, &sig));
    /// ```
    pub fn sign_multi(
        &self,
        m: &Digest,
        shared_nonce: &U256,
        combined_pubkey: &PublicKey,
    ) -> Signature {
        let chal = {
            // scalar = nonce * G
            let scalar = ch_scal_big(shared_nonce, &A_GEN).unwrap();
            let mut transcript: ArrayVec<Belt, { 6 + 6 + 6 + 6 + 5 }> = ArrayVec::new();
            transcript.try_extend_from_slice(&scalar.x.0).unwrap();
            transcript.try_extend_from_slice(&scalar.y.0).unwrap();
            transcript
                .try_extend_from_slice(&combined_pubkey.0.x.0)
                .unwrap();
            transcript
                .try_extend_from_slice(&combined_pubkey.0.y.0)
                .unwrap();
            transcript.try_extend_from_slice(&m.0).unwrap();
            trunc_g_order(&hash_varlen(&transcript))
        };
        let nonce = self.nonce_for(m);
        let chal_mul = MulMod::mul_mod(&chal, &self.0, &G_ORDER);
        let sig = nonce.add_mod(&chal_mul, &G_ORDER);
        Signature { c: chal, s: sig }
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }
}

impl core::ops::Add for &PrivateKey {
    type Output = PrivateKey;

    fn add(self, other: &PrivateKey) -> PrivateKey {
        PrivateKey(self.0.add_mod(&other.0, &G_ORDER))
    }
}

impl core::ops::Add for PrivateKey {
    type Output = PrivateKey;

    fn add(self, other: PrivateKey) -> PrivateKey {
        PrivateKey(self.0.add_mod(&other.0, &G_ORDER))
    }
}

impl core::ops::AddAssign for PrivateKey {
    fn add_assign(&mut self, other: PrivateKey) {
        *self = &*self + &other;
    }
}

impl core::ops::Sub for &PrivateKey {
    type Output = PrivateKey;

    fn sub(self, other: &PrivateKey) -> PrivateKey {
        PrivateKey(self.0.sub_mod(&other.0, &G_ORDER))
    }
}

impl core::ops::SubAssign for PrivateKey {
    fn sub_assign(&mut self, other: PrivateKey) {
        *self = &*self - &other;
    }
}

impl core::iter::Sum<PrivateKey> for PrivateKey {
    fn sum<I: Iterator<Item = PrivateKey>>(iter: I) -> Self {
        iter.fold(PrivateKey(U256::ZERO), |acc, x| &acc + &x)
    }
}

impl<'a> core::iter::Sum<&'a PrivateKey> for PrivateKey {
    fn sum<I: Iterator<Item = &'a PrivateKey>>(iter: I) -> Self {
        iter.fold(PrivateKey(U256::ZERO), |acc, x| &acc + x)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn mupk_test() {
        let privs = [
            U256::from_u64(123),
            U256::from_u64(124),
            G_ORDER.sub_mod(&U256::ONE, &G_ORDER),
        ]
        .map(PrivateKey);
        let pubs = privs.clone().map(|p| p.public_key());
        let pub_key: PublicKey = pubs.iter().sum();
        let priv_key: PrivateKey = privs.iter().sum();
        let pub_key_from_priv = priv_key.public_key();
        assert_eq!(pub_key, pub_key_from_priv);
    }

    #[test]
    fn musig_test() {
        let privs = [
            U256::from_u64(123),
            U256::from_u64(124),
            G_ORDER.sub_mod(&U256::ONE, &G_ORDER),
        ]
        .map(PrivateKey);
        let pubs = privs.clone().map(|p| p.public_key());
        let pub_key: PublicKey = pubs.iter().sum();
        let priv_key: PrivateKey = privs.iter().sum();

        let digest = Digest([Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)]);
        let signature_all = priv_key.sign(&digest);
        // Just testing regular signing
        assert!(pub_key.verify(&digest, &signature_all));

        // Now do split signing
        let nonces = privs
            .iter()
            .map(|p| p.nonce_for(&digest))
            .collect::<Vec<_>>();
        let nonce = PrivateKey::combine_nonces(&nonces);
        let mut sigs = vec![];
        for priv_key in &privs {
            sigs.push(priv_key.sign_multi(&digest, &nonce, &pub_key));
        }
        // Combine all signatures
        let sig = sigs.into_iter().sum::<Option<Signature>>().unwrap();
        // Verify combined signature
        assert!(pub_key.verify(&digest, &sig));
    }

    #[test]
    fn test_sign_and_verify() {
        let priv_key = PrivateKey(U256::from_u64(123));
        let digest = Digest([Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)]);
        let signature = priv_key.sign(&digest);
        let pubkey = priv_key.public_key();
        assert!(
            pubkey.verify(&digest, &signature),
            "Signature verification failed!"
        );

        // Corrupting digest, signature, or pubkey should all cause failure
        let mut wrong_digest = digest;
        wrong_digest.0[0] = Belt(0);
        assert!(
            !pubkey.verify(&wrong_digest, &signature),
            "Should reject wrong digest"
        );
        let mut wrong_sig = signature;
        wrong_sig.s += U256::from_u64(1);
        assert!(
            !pubkey.verify(&digest, &wrong_sig),
            "Should reject wrong signature"
        );
        let mut wrong_pubkey = pubkey;
        wrong_pubkey.0.x.0[0].0 += 1;
        assert!(
            !wrong_pubkey.verify(&digest, &signature),
            "Should reject wrong public key"
        );
    }

    #[test]
    fn test_vector() {
        // from nockchain zkvm-jetpack cheetah_jets.rs test_batch_verify_affine
        let digest = Digest([Belt(8), Belt(9), Belt(10), Belt(11), Belt(12)]);
        let pubkey = PublicKey(CheetahPoint {
            x: F6lt([
                Belt(2754611494552410273),
                Belt(8599518745794843693),
                Belt(10526511002404673680),
                Belt(4830863958577994148),
                Belt(375185138577093320),
                Belt(12938930721685970739),
            ]),
            y: F6lt([
                Belt(3062714866612034253),
                Belt(15671931273416742386),
                Belt(4071440668668521568),
                Belt(7738250649524482367),
                Belt(5259065445844042557),
                Belt(8456011930642078370),
            ]),
            inf: false,
        });
        let c_hex = "6f3cd43cd8709f4368aed04cd84292ab1c380cb645aaa7d010669d70375cbe88";
        let s_hex = "5197ab182e307a350b5cf3606d6e99a6f35b0d382c8330dde6e51fb6ef8ebb8c";
        let signature = Signature {
            c: U256::from_str_radix_vartime(c_hex, 16).unwrap(),
            s: U256::from_str_radix_vartime(s_hex, 16).unwrap(),
        };
        assert!(pubkey.verify(&digest, &signature));
    }
}
