use crate::keystore::{KeyHandle, PublicKey};

pub struct Name;
pub struct Coins(pub u64);
pub struct Recipient {
    pub m: u32,
    pub pubkeys: Vec<PublicKey>,
    pub gift: Coins,
}
pub struct LockIntent;
pub struct Draft;

// NOTE: this is called by TxEngine
pub fn create_tx(
    names: &[Name],
    fee: Coins,
    recipients: &[Recipient],
    lock_intent: LockIntent,
) -> Draft {
    todo!()
}

pub fn sign_tx(draft: Draft, handle: KeyHandle) -> Draft {
    todo!()
}
