use curv::{FE, GE};
use crate::signer_node::BidirectionalSharedSecretMap;
use crate::blockdata::Block;
use crate::net::SignerID;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum NodeState {
    Joining,
    Master {
        /// *block_key* is random value for using int the Signature Issuing Protocol.
        /// VSS which is distributed to each other signer is generated by this key. All signers in
        /// all block generation rounds has each own block_key.
        block_key: Option<FE>,
        shared_block_secrets: BidirectionalSharedSecretMap,
        block_shared_keys: Option<(bool, FE, GE)>,
        candidate_block: Option<Block>,
        signatures: BTreeMap<SignerID, (FE, FE)>,
        round_is_done: bool,
    },
    Member {
        /// *block_key* is random value for using int the Signature Issuing Protocol.
        /// VSS which is distributed to each other signer is generated by this key. All signers in
        /// all block generation rounds has each own block_key.
        block_key: Option<FE>,
        shared_block_secrets: BidirectionalSharedSecretMap,
        block_shared_keys: Option<(bool, FE, GE)>,
        candidate_block: Option<Block>,
        master_index: usize,
    },
    RoundComplete {
        master_index: usize,
        next_master_index: usize,
    },
}

pub mod builder {
    use crate::blockdata::Block;
    use crate::net::SignerID;
    use crate::signer_node::{BidirectionalSharedSecretMap, NodeState, INITIAL_MASTER_INDEX};
    use curv::{FE, GE};
    use std::collections::BTreeMap;

    pub trait Builder {
        fn build(&self) -> NodeState;
    }

    pub struct Master {
        block_key: Option<FE>,
        shared_block_secrets: BidirectionalSharedSecretMap,
        block_shared_keys: Option<(bool, FE, GE)>,
        candidate_block: Option<Block>,
        signatures: BTreeMap<SignerID, (FE, FE)>,
        round_is_done: bool,
    }

    impl Builder for Master {
        fn build(&self) -> NodeState {
            NodeState::Master {
                block_key: self.block_key.clone(),
                shared_block_secrets: self.shared_block_secrets.clone(),
                block_shared_keys: self.block_shared_keys.clone(),
                candidate_block: self.candidate_block.clone(),
                signatures: self.signatures.clone(),
                round_is_done: self.round_is_done,
            }
        }
    }

    impl Default for Master {
        fn default() -> Self {
            Self {
                block_key: None,
                shared_block_secrets: BidirectionalSharedSecretMap::new(),
                block_shared_keys: None,
                candidate_block: None,
                signatures: BTreeMap::new(),
                round_is_done: false,
            }
        }
    }

    impl Master {
        pub fn new(
            block_key: Option<FE>,
            shared_block_secrets: BidirectionalSharedSecretMap,
            block_shared_keys: Option<(bool, FE, GE)>,
            candidate_block: Option<Block>,
            signatures: BTreeMap<SignerID, (FE, FE)>,
            round_is_done: bool,
        ) -> Self {
            Self {
                block_key,
                shared_block_secrets,
                block_shared_keys,
                candidate_block,
                signatures,
                round_is_done,
            }
        }

        pub fn block_key(&mut self, block_key: Option<FE>) -> &mut Self {
            self.block_key = block_key;
            self
        }

        pub fn shared_block_secrets(
            &mut self,
            shared_block_secrets: BidirectionalSharedSecretMap,
        ) -> &mut Self {
            self.shared_block_secrets = shared_block_secrets;
            self
        }

        pub fn block_shared_keys(&mut self, block_shared_keys: Option<(bool, FE, GE)>) -> &mut Self {
            self.block_shared_keys = block_shared_keys;
            self
        }

        pub fn candidate_block(&mut self, candidate_block: Option<Block>) -> &mut Self {
            self.candidate_block = candidate_block;
            self
        }

        pub fn signatures(&mut self, signatures: BTreeMap<SignerID, (FE, FE)>) -> &mut Self {
            self.signatures = signatures;
            self
        }

        pub fn round_is_done(&mut self, round_is_done: bool) -> &mut Self {
            self.round_is_done = round_is_done;
            self
        }
    }

    pub struct Member {
        block_key: Option<FE>,
        shared_block_secrets: BidirectionalSharedSecretMap,
        block_shared_keys: Option<(bool, FE, GE)>,
        candidate_block: Option<Block>,
        master_index: usize,
    }

    impl Default for Member {
        fn default() -> Self {
            Self {
                block_key: None,
                shared_block_secrets: BidirectionalSharedSecretMap::new(),
                block_shared_keys: None,
                candidate_block: None,
                master_index: INITIAL_MASTER_INDEX,
            }
        }
    }

    impl Builder for Member {
        fn build(&self) -> NodeState {
            NodeState::Member {
                block_key: self.block_key.clone(),
                shared_block_secrets: self.shared_block_secrets.clone(),
                block_shared_keys: self.block_shared_keys.clone(),
                candidate_block: self.candidate_block.clone(),
                master_index: self.master_index,
            }
        }
    }

    impl Member {
        pub fn new(
            block_key: Option<FE>,
            shared_block_secrets: BidirectionalSharedSecretMap,
            block_shared_keys: Option<(bool, FE, GE)>,
            candidate_block: Option<Block>,
            master_index: usize,
        ) -> Self {
            Self {
                block_key,
                shared_block_secrets,
                block_shared_keys,
                candidate_block,
                master_index,
            }
        }

        pub fn block_key(&mut self, block_key: Option<FE>) -> &mut Self {
            self.block_key = block_key;
            self
        }

        pub fn shared_block_secrets(
            &mut self,
            shared_block_secrets: BidirectionalSharedSecretMap,
        ) -> &mut Self {
            self.shared_block_secrets = shared_block_secrets;
            self
        }

        pub fn block_shared_keys(&mut self, block_shared_keys: Option<(bool, FE, GE)>) -> &mut Self {
            self.block_shared_keys = block_shared_keys;
            self
        }

        pub fn candidate_block(&mut self, candidate_block: Option<Block>) -> &mut Self {
            self.candidate_block = candidate_block;
            self
        }

        pub fn master_index(&mut self, master_index: usize) -> &mut Self {
            self.master_index = master_index;
            self
        }
    }
}