// Code required to mint Dbcs
// The in the most basic terms means
// a valid input DBC can be split into
// 1 or more DBCs as long as
// input is vaid
// Outputs <= input value
use crate::{Dbc, DbcSpent};
/*
Algorithm
Take an input DBC and return output dbcContent(s)
To create a valid DBC the Mint must sign this after doing some checks.
verify that the dbc contents was part of the parent spend transaction.
    hash(dbc.content) ∈ dbc.parent_spent.outputs
    dbc.content.parent == dbc.parent_spent.input

If we don’t recognize the dbc.section_key, fetch a proof chain from the section
responsible for XorName(hash(dbc.parent_spent.input)) and validated the proof chain
 as well as that dbc.section_key is present in the chain.
Cache the dbc.section_key
Verify the dbc.section_sig signature is a valid signature of dbc.parent_spent.
dbc.section_key.verify(dbc.section_sig, hash(dbc.parent_spent))
Outputs signed with BLS public key share
*/
fn mint(input: Dbc, output: Vec<Dbc>) -> Option<DbcSpent> {
    unimplemented!();
}
// Notes
// Network state
// The network MUST record spent DBC's
// It MAY also store a mint request and lock that request
// It may also be used to select any set of valid outputs
