# hypercore-crypto

The crypto primitives used in hypercore, extracted into a separate module

```
npm install hypercore-crypto
```

## Usage

```js
const crypto = require('hypercore-crypto')

const keyPair = crypto.keyPair()
console.log(keyPair) // prints an ML-DSA keypair
```

## API

#### `keyPair = crypto.keyPair()`

Returns an `ML-DSA-44` keypair that can be used for tree signing.

If `seed` is provided, the key pair is deterministically derived through `crypto.mlDsaKeyPair(seed)`.

#### `signature = crypto.sign(message, secretKey)`

Signs a message (buffer) with ML-DSA.

#### `verified = crypto.verify(message, signature, publicKey)`

Verifies an ML-DSA signature for a message.

#### `valid = crypto.validateKeyPair({ publicKey, secretKey })`

Validates that the secret key and public key belong to the same ML-DSA key pair.

#### `keyPair = crypto.encryptionKeyPair([seed])`

Returns an `ML-KEM-512` encryption key pair.

If `seed` is provided, the key pair is deterministically derived through `crypto.mlDemKeyPair(seed)`.

#### `ciphertext = crypto.encrypt(message, publicKey)`

Encrypts a message to `publicKey`.

- For ML-KEM keys, this uses a PQ KEM+AEAD construction.
- For legacy key sizes, the previous sodium sealed box path is retained for compatibility.

#### `plaintext = crypto.decrypt(ciphertext, keyPair)`

Decrypts a ciphertext and returns the plaintext, or `null` if decryption/authentication fails.

#### `output = crypto.kdf(primaryKey, namespace, [length = 32])`

Derives deterministic key material from a shared `primaryKey` and a domain-separating `namespace`.

#### `keyPair = crypto.mlDsaKeyPair(primaryKey, [namespace])`

Derives an `ML-DSA-44` key pair from `primaryKey` and `namespace`.
Defaults to namespace `hypercore-crypto/v4/mldsa`.

#### `keyPair = crypto.mlDemKeyPair(primaryKey, [namespace])`

Derives an `ML-KEM-512` key pair from `primaryKey` and `namespace`.
Defaults to namespace `hypercore-crypto/v4/mldem`.

#### `hash = crypto.data(data)`

Hashes a leaf node in a merkle tree.

#### `hash = crypto.parent(left, right)`

Hash a parent node in a merkle tree. `left` and `right` should look like this:

```js
{
  index: treeIndex,
  hash: hashOfThisNode,
  size: byteSizeOfThisTree
}
```

#### `hash = crypto.tree(peaks)`

Hashes the merkle root of the tree. `peaks` should be an array of the peaks of the tree and should look like above.

#### `buffer = crypto.randomBytes(size)`

Returns a buffer containing random bytes of size `size`.

#### `hash = crypto.discoveryKey(publicKey)`

Return a hash derived from a `publicKey` that can be used for discovery
without disclosing the public key.

#### `list = crypto.namespace(name, count)`

Make a list of namespaces from a specific publicly known name.
Use this to namespace capabilities or hashes / signatures across algorithms.

## License

MIT
