// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use std::collections::BTreeMap;

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::traits::*;
use curv::{BigInt, FE, GE};
use multi_party_schnorr::protocols::thresholdsig::bitcoin_schnorr::*;

use crate::blockdata::BlockHash;
use crate::errors::Error;
use crate::net::SignerID;
use crate::signer_node::SharedSecretMap;

pub struct Sign;

impl Sign {
    pub fn private_key_to_big_int(key: secp256k1::SecretKey) -> Option<BigInt> {
        let value = format!("{}", key);
        let n = BigInt::from_hex(&value);
        Some(n)
    }

    pub fn create_key(index: usize, pk: Option<BigInt>) -> Keys {
        let u: FE = match pk {
            Some(i) => ECScalar::from(&i),
            None => ECScalar::new_random(),
        };
        let y = &ECPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index.clone(),
        }
    }

    pub fn sign(
        eph_shared_keys: &BTreeMap<SignerID, (FE, GE, GE, VerifiableSS)>,
        priv_shared_keys: &BTreeMap<SignerID, (FE, GE, GE, VerifiableSS)>,
        eph_shared_secrets: &SharedSecretMap,
        priv_shared_secrets: &SharedSecretMap,
        eph_y_vec: Vec<GE>,
        priv_sum: GE,
        message: BlockHash,
        n: usize,
    ) -> Result<String, Error> {
        let eph_shared_keys_vec: Vec<SharedKeys> = eph_shared_keys
            .values()
            .map(|i| SharedKeys { x_i: i.0, y: i.1 })
            .collect();
        let priv_shared_keys_vec: Vec<SharedKeys> = priv_shared_keys
            .values()
            .map(|i| SharedKeys { x_i: i.0, y: i.1 })
            .collect();

        let message_slice = message.borrow_inner();
        let local_sig_vec = (0..n)
            .map(|i| {
                LocalSig::compute(
                    &message_slice.clone(),
                    &eph_shared_keys_vec[i],
                    &priv_shared_keys_vec[i],
                )
            })
            .collect::<Vec<LocalSig>>();
        let key_gen_vss_vec: Vec<VerifiableSS> = priv_shared_secrets
            .values()
            .cloned()
            .map(|i| i.vss.clone())
            .collect();
        let eph_vss_vec: Vec<VerifiableSS> = eph_shared_secrets
            .values()
            .cloned()
            .map(|i| i.vss.clone())
            .collect();
        let parties = (0..n).collect::<Vec<usize>>();
        let verify_local_sig = LocalSig::verify_local_sigs(
            &local_sig_vec,
            &parties[..],
            &key_gen_vss_vec,
            &eph_vss_vec,
        );
        if verify_local_sig.is_err() {
            log::error!("verify error!");
            // start round robin of master node.
            return Err(Error::InvalidLocalSignature);
        }

        let vss_sum_local_sigs = verify_local_sig.unwrap();
        let signature =
            Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties, priv_sum);
        let verify_sig = signature.verify(message_slice, &eph_y_vec[0]);
        match verify_sig {
            Ok(_) => {
                let as_int = signature.sigma.to_big_int();
                let mut array: Vec<u8> = curv::arithmetic::traits::Converter::to_vec(&as_int);
                let v_as_int = signature.v.x_coor().unwrap();
                array.extend(curv::arithmetic::traits::Converter::to_vec(&v_as_int));
                let bitcoin_sig = secp256k1::Signature::from_compact(&array[..]).unwrap();
                let s = format!("{}", bitcoin_sig);
                Ok(s)
            }
            Err(_) => {
                log::error!("verify error!");
                Err(Error::InvalidAggregatedSignature)
            }
        }
    }
}
