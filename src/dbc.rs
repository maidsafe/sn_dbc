use crate::{DbcContent, Hash};
struct Dbc {
    content: DbcContent,
    parent_spent: DbcSpent,
    mint_key: PubKey,
    mint_sig: Signature, // (self.parent_spent),
}
impl Dbc {
    // Take an input DBC and return output dbcContent(s)
    // To create a valid DBC the Mint must sign this after doing some checks.
    // verify that the dbc contents was part of the parent spend transacition.
    //     hash(dbc.content) ∈ dbc.parent_spent.outputs
    //     dbc.content.parent == dbc.parent_spent.input

    // If we don’t recognize the dbc.section_key, fetch a proof chain from the section
    // responsible for XorName(hash(dbc.parent_spent.input)) and validated the proof chain
    //  as well as that dbc.section_key is present in the chain.
    // Cache the dbc.section_key
    // Verify the dbc.section_sig signature is a valid signature of dbc.parent_spent.
    // dbc.section_key.verify(dbc.section_sig, hash(dbc.parent_spent))
    // Outputs signed with BLS public key share
    pub fn mint(input: Dbc, outputs: Vec<Dbc>) -> Result<Error, Vec<Self>> {}
}
