Use std:Error;
// Code required to mint Dbcs
// The in the most basic terms means
// a valid input DBC can be split into
// 1 or more DBCs as long as 
// input is vaid
// Outputs <= input value 
use crate::{Dbc, DbcSpent};

fn mint(input: Dbc, output :Vec<Dbc>)-> Result<Error,DbcSpent> {
  unimplemented!();
}

// Network state
// The network MUST record spent DBC's
// It MAY also store a mint request and lock that request
// It may also be used to select any set of valid outputs
