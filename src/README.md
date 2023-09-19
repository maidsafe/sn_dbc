# Digital Bearer Certificates for the Safe network.

### Basics:
A user has a main key - `MainSecretKey` - which is a `bls::SecretKey`.
It is in essense a key _pair_, as the corresponding `bls::PublicKey` can be gotten from that secret key.
The `bls::PublicKey`of that key pair, is the `MainPubkey` to which anyone can send tokens.

- A `CashNote` is a container that holds value (counted in tokens).

- A `CashNote` has a unique identifier, `UniquePubkey`, which is a `bls::PublicKey`.
The corresponding `bls::SecretKey` called `DerivedSecretKey`, unlocks the value.

- A `CashNote` can only be fully spent. So you unlock it and take out all the tokens, and the `CashNote` is spent.

- A `CashNote` cannot be made public as it contains secrets, what the Network only ever sees is `SignedSpend`, which tells us which `CashNote` was spent

### Sending tokens:
When you send tokens to someone, you create a new `CashNote`, with a `UniquePubkey` (a `bls::PublicKey`) by deriving it from the `MainPubkey` (a `bls::PublicKey`) of someone. You derive it using a random `DerivationIndex`, which you include in the newly created `CashNote`.
Also included in this new `CashNote` are the signatures of network nodes verifying that the input `CashNote(s)` that you emptied to create this new `CashNote`, are actually spent and was included in the transaction where this new `CashNote` was created. (The signatures part will change with the new network design.)
Since `CashNote`s contain secrets, they should be encrypted before being sent. 

### Unknown connection between CashNotes and MainPubkeyes:
Since the `UniquePubkey` is derived from the `MainPubkey`, using a secret `DerivationIndex`, no one except sender and receiver knows that this new `CashNote` was sent to the `MainPubkey` of the receiver.
