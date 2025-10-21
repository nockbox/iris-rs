use ibig::UBig;
use nbx_ztd::{
    crypto::cheetah::{
        ch_add, ch_neg, ch_scal_big, trunc_g_order, CheetahPoint, F6lt, A_GEN, G_ORDER,
    },
    tip5::hash::hash_varlen,
    Belt, Digest,
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PublicKey(pub CheetahPoint);

impl PublicKey {
    pub fn verify(&self, m: &Digest, sig: &Signature) -> bool {
        if sig.c == UBig::from(0u64)
            || sig.c >= *G_ORDER
            || sig.s == UBig::from(0u64)
            || sig.s >= *G_ORDER
        {
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
            let mut transcript: Vec<Belt> = Vec::new();
            transcript.extend_from_slice(&scalar.x.0);
            transcript.extend_from_slice(&scalar.y.0);
            transcript.extend_from_slice(&self.0.x.0);
            transcript.extend_from_slice(&self.0.y.0);
            transcript.extend_from_slice(&m.0);
            trunc_g_order(&hash_varlen(&mut transcript))
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

    /// SLIP-10 compatible serialization (legacy 65-byte format for compatibility)
    pub(crate) fn to_slip10_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        for belt in self.0.y.0.iter().rev().chain(self.0.x.0.iter().rev()) {
            data.extend_from_slice(&belt.0.to_be_bytes());
        }
        data
    }

    pub fn from_be_bytes(bytes: &[u8; 97]) -> PublicKey {
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
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub c: UBig, // challenge
    pub s: UBig, // signature scalar
}

#[derive(Debug, Clone)]
pub struct PrivateKey(pub UBig);

impl PrivateKey {
    pub fn derive_public_key(&self) -> PublicKey {
        PublicKey(ch_scal_big(&self.0, &A_GEN).unwrap())
    }

    pub fn sign(&self, m: &Digest) -> Signature {
        let pubkey = self.derive_public_key().0;
        let nonce = {
            let mut transcript = Vec::new();
            transcript.extend_from_slice(&pubkey.x.0);
            transcript.extend_from_slice(&pubkey.y.0);
            transcript.extend_from_slice(&m.0);
            trunc_g_order(&hash_varlen(&mut transcript))
        };
        let chal = {
            // scalar = nonce * G
            let scalar = ch_scal_big(&nonce, &A_GEN).unwrap();
            let mut transcript = Vec::new();
            transcript.extend_from_slice(&scalar.x.0);
            transcript.extend_from_slice(&scalar.y.0);
            transcript.extend_from_slice(&pubkey.x.0);
            transcript.extend_from_slice(&pubkey.y.0);
            transcript.extend_from_slice(&m.0);
            trunc_g_order(&hash_varlen(&mut transcript))
        };
        let sig = (&nonce + &chal * &self.0) % &*G_ORDER;
        Signature { c: chal, s: sig }
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_be_bytes();
        let mut arr = [0u8; 32];
        arr[32 - bytes.len()..].copy_from_slice(&bytes);
        arr
    }

    pub fn from_be_bytes(bytes: &[u8; 32]) -> PrivateKey {
        PrivateKey(UBig::from_be_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let priv_key = PrivateKey(UBig::from(123u64));
        let digest = Digest([Belt(1), Belt(2), Belt(3), Belt(4), Belt(5)]);
        let signature = priv_key.sign(&digest);
        let pubkey = priv_key.derive_public_key();
        assert!(
            pubkey.verify(&digest, &signature),
            "Signature verification failed!"
        );

        // Corrupting digest, signature, or pubkey should all cause failure
        let mut wrong_digest = digest.clone();
        wrong_digest.0[0] = Belt(0);
        assert!(
            !pubkey.verify(&wrong_digest, &signature),
            "Should reject wrong digest"
        );
        let mut wrong_sig = signature.clone();
        wrong_sig.s += UBig::from(1u64);
        assert!(
            !pubkey.verify(&digest, &wrong_sig),
            "Should reject wrong signature"
        );
        let mut wrong_pubkey = pubkey.clone();
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
            c: UBig::from_str_radix(c_hex, 16).unwrap(),
            s: UBig::from_str_radix(s_hex, 16).unwrap(),
        };
        assert!(pubkey.verify(&digest, &signature));
    }
}
