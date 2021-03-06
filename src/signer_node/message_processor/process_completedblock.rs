use crate::blockdata::Block;
use crate::net::SignerID;
use crate::rpc::TapyrusApi;
use crate::signer_node::{is_master, master_index, next_master_index, NodeParameters, NodeState};

pub fn process_completedblock<T>(
    sender_id: &SignerID,
    _block: &Block,
    prev_state: &NodeState,
    params: &NodeParameters<T>,
) -> NodeState
where
    T: TapyrusApi,
{
    if !is_master(sender_id, prev_state, params) {
        log::warn!("Peer {} may be malicious node. It might impersonate as master or your node might be behind from others.", sender_id);
        return prev_state.clone(); // Ignore message
    }

    NodeState::RoundComplete {
        master_index: master_index(prev_state, params)
            .expect("Previous state getting round complete should have round master"),
        next_master_index: next_master_index(prev_state, params),
    }
}

#[cfg(test)]
mod tests {
    use super::process_completedblock;
    use crate::net::SignerID;
    use crate::signer_node::{master_index, NodeState};
    use crate::tests::helper::blocks::get_block;
    use crate::tests::helper::keys::TEST_KEYS;
    use crate::tests::helper::node_parameters_builder::NodeParametersBuilder;
    use crate::tests::helper::node_state_builder::{Builder, Member};
    use crate::tests::helper::rpc::MockRpc;

    #[test]
    fn test_process_completedblock() {
        let block = get_block(0);
        let mut rpc = MockRpc::new();
        // It should call testproposedblock RPC once.
        rpc.should_call_testproposedblock(Ok(true));
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        // check 1, next_master_index should be incremented after process completeblock message.
        let prev_state = Member::new().master_index(0).build();
        let sender_id = SignerID::new(TEST_KEYS.pubkeys()[1]);
        let state = process_completedblock(&sender_id, &block, &prev_state, &params);

        match &state {
            NodeState::RoundComplete {
                next_master_index, ..
            } => assert_eq!(*next_master_index, 1),
            n => assert!(false, "Should be Member, but state:{:?}", n),
        }

        // check 2, next master index should be back to 0 if the previous master index is the last number.
        let prev_state = Member::new().master_index(4).build();
        let sender_id = SignerID::new(TEST_KEYS.pubkeys()[0]);
        let state = process_completedblock(&sender_id, &block, &prev_state, &params);

        match &state {
            NodeState::RoundComplete {
                next_master_index, ..
            } => assert_eq!(*next_master_index, 0),
            n => assert!(false, "Should be Member, but state:{:?}", n),
        }
    }

    #[test]
    fn test_process_completedblock_ignore_different_master() {
        let block = get_block(0);
        let mut rpc = MockRpc::new();
        // It should call testproposedblock RPC once.
        rpc.should_call_testproposedblock(Ok(true));
        let params = NodeParametersBuilder::new().rpc(rpc).build();

        let prev_state = Member::new().master_index(0).build();
        let sender_id = SignerID::new(TEST_KEYS.pubkeys()[0]);
        let state = process_completedblock(&sender_id, &block, &prev_state, &params);

        // It should not incremented if not recorded master.
        assert_eq!(master_index(&state, &params).unwrap(), 0);
        match state {
            NodeState::Member { .. } => assert!(true),
            n => panic!("Should be Member, but state:{:?}", n),
        }
    }
}
