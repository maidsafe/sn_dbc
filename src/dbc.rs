use crate::{DbcContent, Hash};
struct Dbc {
    content: DbcContent,
    parent_spent: DbcSpent,
    mint_key: PubKey,
    mint_sig: Signature, // (self.parent_spent),
}
impl Dbc {
    pub fn mint(input: Dbc, outputs: Vec<Dbc>) -> Result<Error, Vec<Self>> {}
}
