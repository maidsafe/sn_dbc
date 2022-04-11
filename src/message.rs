// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{Dbc, KeyImage, OwnerOnce, SpentProofShare};
use bls_ringct::ringct::{Amount, RingCtTransaction};
use std::fmt;

use serde::{Deserialize, Serialize};

/// Messages used for running DBC.
#[derive(Clone, Deserialize, Serialize)]
pub enum Message {
    Issue {
        starting_dbc: Dbc,
        amount: Amount,
        receive_owner: OwnerOnce,
    },
    AddSpentProof(SpentProofShare),
    CreateTransaction {
        input_dbc: Dbc,
        amount: Amount,
        output_owner: OwnerOnce,
    },
    WriteTransaction {
        key_image: KeyImage,
        transaction: RingCtTransaction,
    },
}

impl fmt::Debug for Message {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match &*self {
            Message::Issue {
                starting_dbc,
                amount,
                receive_owner,
            } => write!(
                formatter,
                "Issue amount {:?} from {:?} to {:?}",
                amount, starting_dbc, receive_owner
            ),
            Message::AddSpentProof(spent_proof_share) => {
                write!(formatter, "AddSpentProof({:?})", spent_proof_share)
            }
            Message::CreateTransaction {
                input_dbc,
                amount,
                output_owner,
            } => write!(
                formatter,
                "CreateTransaction of amount {:?} from {:?} to {:?}",
                amount, input_dbc, output_owner
            ),
            Message::WriteTransaction {
                key_image,
                transaction,
            } => {
                write!(
                    formatter,
                    "WriteTransaction {:?} of {:?}",
                    transaction, key_image
                )
            }
        }
    }
}
