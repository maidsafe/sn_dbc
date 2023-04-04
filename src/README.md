# Digital Bearer Certificates for the Safe network.

### Basics:
A user has a main key - `MainKey` - which is a `bls::SecretKey`.
It is in essense a key _pair_, as the corresponding `bls::PublicKey` can be gotten from that secret key.
The `bls::PublicKey`of that key pair, is the `PublicAddress` to which anyone can send tokens.

- A `Dbc` is a vehicle for transfering tokens.

- A `Dbc` has a unique identifier, `DbcId`, which is a `bls::PublicKey`.
The corresponding `bls::SecretKey` called `DerivedKey`, unlocks the value.

- A `Dbc` can only be fully spent. So you unlock it and take out all the tokens, and the `Dbc` is spent.

### Sending tokens:
When you send tokens to someone, you create a new `Dbc`, with a `DbcId` (a `bls::PublicKey`) by deriving it from the `PublicAddress` (a `bls::PublicKey`) of someone. You derive it using a random `DerivationIndex`, which you include (encrypted to the `PublicAddress`, which means only the corresponding `MainKey` can decrypt it) in the newly created `Dbc`.
Also included in this new `Dbc` are the signatures of network nodes verifying that the input `Dbc(s)` that you emptied to create this new `Dbc`, are actually spent and was included in the transaction where this new `Dbc` was created. (The signatures part will change with the new network design.)

### Unknown connection between Dbcs and PublicAddresses:
Since the `DbcId` is derived from the `PublicAddress`, using a secret `DerivationIndex`, no one except sender and receiver knows that this new `Dbc` was sent to the `PublicAddress` of the receiver.
The recipient decrypts the `DerivationIndex` cipher, using their `MainKey` (remember, it's the corresponding `bls::SecretKey` of the `bls::PublicKey` in the `PublicAddress`).

### Unknown amounts in Dbcs:
Also, the amount in the `Dbc` is blinded, using a `BlindingFactor` which is encrypted to the `DbcId` (meaning, that only the holder of the `DerivedKey` corresponding to that `DbcId`, can decrypt it).
The recipient can derive the `DerivedKey` (a `bls::SecretKey`) that corresponds to the `DbcId`, using the same decrypted `DerivationIndex` mentioned above.
With that `DerivedKey`, the recipient can now decrypt the `BlindingFactor` as to unblind the amount, and verify it is the expected amount, and that very `DerivedKey` also unlocks this new `Dbc`, as to use the tokens within.
