use super::{Digest, Hashable, NounDecode, NounEncode};
use alloc::vec::Vec;
#[cfg(feature = "wasm")]
use alloc::{boxed::Box, format, string::ToString};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd_derive::wasm_noun_codec]
pub struct MerkleProof {
    pub root: Digest,
    pub path: Vec<Digest>,
}

#[derive(Debug, Clone, NounEncode, NounDecode, Hashable, Serialize, Deserialize)]
#[iris_ztd_derive::wasm_noun_codec]
pub struct MerkleProvenAxis {
    pub proof: MerkleProof,
    pub axis: u64,
}

impl MerkleProof {
    /// Prove a 0-indexed leaf
    ///
    /// This is important - unlike `prove-hashable-by-index:merkle` the index here is 0-based, not 1.
    pub fn prove_hashable<T: Hashable>(item: &T, index: usize) -> MerkleProvenAxis {
        let Some((left, right)) = item.hashable_pair() else {
            return MerkleProvenAxis {
                proof: Self {
                    root: item.hash(),
                    path: Vec::new(),
                },
                axis: 1,
            };
        };
        let lc = left.leaf_count();
        if index < lc {
            let mut rec = Self::prove_hashable(&left, index);
            let sib = right.hash();
            rec.proof.root = (rec.proof.root, sib).hash();
            rec.proof.path.push(sib);
            // This is like peg, but we invert the bit pattern, because we are implicitly flipping the leading 1 as well
            let alz = rec.axis.leading_zeros();
            rec.axis ^= 0b11 << (63 - alz);
            rec
        } else {
            let mut rec = Self::prove_hashable(&right, index - lc);
            let sib = left.hash();
            rec.proof.root = (sib, rec.proof.root).hash();
            rec.proof.path.push(sib);
            let alz = rec.axis.leading_zeros();
            rec.axis ^= 0b10 << (63 - alz);
            rec
        }
    }

    pub fn verify(&self, mut axis: u64, hashable: &impl Hashable) -> bool {
        if axis == 0 {
            return false;
        }
        let mut leaf = hashable.hash();
        let mut path = &self.path[..];

        while axis > 3 {
            let Some((sib, rest)) = path.split_first() else {
                return false;
            };
            path = rest;
            if axis.is_multiple_of(2) {
                leaf = (leaf, sib).hash();
            } else {
                leaf = (sib, leaf).hash();
            }
            axis /= 2;
        }

        if axis == 1 {
            self.root == leaf && path.is_empty()
        } else if axis == 2 && path.len() == 1 {
            self.root == (leaf, path[0]).hash()
        } else if axis == 3 && path.len() == 1 {
            self.root == (path[0], leaf).hash()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashableList;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn test_empty_proof() {
        let MerkleProvenAxis { proof, axis } = MerkleProof::prove_hashable(&(), 0);
        assert_eq!(axis, 1);
        assert_eq!(proof.root.to_string(), ().hash().to_string());
        assert_eq!(proof.path.len(), 0);
        assert!(proof.verify(axis, &()));
    }

    #[test]
    fn test_left_proof() {
        let MerkleProvenAxis { proof, axis } = MerkleProof::prove_hashable(&((), ()), 0);
        assert_eq!(axis, 2);
        assert_eq!(
            proof.root.to_string(),
            "3LPSS51pUxLaxMD8VjyBSW6S9sotLpfx65zibBvm5k1xu18qt5ZGp3S"
        );
        assert_eq!(
            proof.path.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            ["3Ssr4tiWsbX5CE3AG6p5qPHP51fiyvtt1XEEHmSbGgDjp3qjUew6DFB"]
        );
        assert!(proof.verify(axis, &()));
    }

    #[test]
    fn test_right_proof() {
        let MerkleProvenAxis { proof, axis } = MerkleProof::prove_hashable(&((), ()), 1);
        assert_eq!(
            proof.root.to_string(),
            "3LPSS51pUxLaxMD8VjyBSW6S9sotLpfx65zibBvm5k1xu18qt5ZGp3S"
        );
        assert_eq!(
            proof.path.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            ["3Ssr4tiWsbX5CE3AG6p5qPHP51fiyvtt1XEEHmSbGgDjp3qjUew6DFB"]
        );
        assert_eq!(axis, 3);
        assert!(proof.verify(axis, &()));
    }

    #[test]
    fn test_complex_proof() {
        let MerkleProvenAxis { proof, axis } =
            MerkleProof::prove_hashable(&((1u64, 2u64), (3u64, 4u64)), 2);
        assert_eq!(
            proof.root.to_string(),
            "9BC9gRQaJ7Ub4SivF6NmPBQrmqfwdKeDSkbkRjmnKf9yYscct3AcohH"
        );
        assert_eq!(
            proof.path.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            [
                "CdEJceqNNH5iCGYEsWhRf2gHE37zbJXVkVPLpfWW7uYrJjt8magUvgi",
                "BqxDmSrtFP6QsDuoYxjaFxedEzGpy7gfwhmtZnD25FxeedB1ssNPH4t"
            ]
        );
        assert_eq!(axis, 6);
        assert!(proof.verify(axis, &3u64));
    }

    #[test]
    fn test_list_proof() {
        let lst = vec![0u64, 1u64];
        let lst = HashableList(&lst[..]);
        let MerkleProvenAxis { proof, axis } = MerkleProof::prove_hashable(&(&lst, ()), 0);
        assert_eq!(axis, 2);
        assert_eq!(
            proof.root.to_string(),
            "8cSTFCsmaL4KTMVq6RQSQaMMMQfb3YpT6xR1YmnRtG7P4WurnhRRDbM"
        );
        assert_eq!(
            proof.path.iter().map(|v| v.to_string()).collect::<Vec<_>>(),
            ["3Ssr4tiWsbX5CE3AG6p5qPHP51fiyvtt1XEEHmSbGgDjp3qjUew6DFB"]
        );
        assert!(proof.verify(axis, &lst));
    }
}
