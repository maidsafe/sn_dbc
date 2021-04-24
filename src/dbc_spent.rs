/// The spent identifier of the outputs created from this input
/// Note these are hashes and not identifiers as the Dbc is not addressable on the network.
/// i.e. a Dbc can be stored anywhere, even offline.
struct DbcSpent {
    input: DbcContentHash,
    output: Vec<DbcContentHash>,
}
