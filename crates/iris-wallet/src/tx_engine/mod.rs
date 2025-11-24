use crate::draft::{Coins, Draft, LockIntent, Recipient};

struct TxEngine {
    // per pubkey:
    // available notes
    // spent notes
    // transactions
}

impl TxEngine {
    pub fn create_tx(
        &self,
        fee: Coins,
        recipients: &[Recipient],
        lock_intent: LockIntent,
    ) -> Draft {
        todo!()
    }
}
