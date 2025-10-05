const { ristretto255, ristretto255_hasher } = require('@noble/curves/ed25519.js')
const { sha256 } = require('@noble/hashes/sha2.js')
const { randomBytes: nobleRandomBytes } = require('@noble/hashes/utils.js')
const c = require('compact-encoding')
const b4a = require('b4a')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = b4a.from([0])
const PARENT_TYPE = b4a.from([1])
const ROOT_TYPE = b4a.from([2])

const HYPERCORE = b4a.from('hypercore')

exports.keyPair = function (seed) {
  // key pairs might stay around for a while, so better not to use a default slab to avoid retaining it completely
  const slab = b4a.allocUnsafeSlow(32 + 64) // 32 bytes for public key, 64 bytes for secret key
  const publicKey = slab.subarray(0, 32)
  const secretKey = slab.subarray(32)

  let privateKeyScalar
  if (seed) {
    // Use seed to generate deterministic private key
    privateKeyScalar = ristretto255_hasher.hashToScalar(seed)
  } else {
    // Generate random private key using ristretto255 scalar generation
    privateKeyScalar = ristretto255_hasher.hashToScalar(nobleRandomBytes(32))
  }

  // Derive public key using ristretto255
  const publicKeyPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
  
  // Write private key to first 32 bytes of secret key
  const privateKeyBytes = ristretto255.Point.Fn.toBytes(privateKeyScalar)
  secretKey.set(privateKeyBytes, 0, 32)
  
  // Write public key to both publicKey buffer and last 32 bytes of secret key
  const publicKeyBytes = publicKeyPoint.toBytes()
  publicKey.set(publicKeyBytes)
  secretKey.set(publicKeyBytes, 32, 32)

  return {
    publicKey,
    secretKey
  }
}

exports.validateKeyPair = function (keyPair) {
  try {
    const pk = b4a.allocUnsafe(32)
    // Extract the private key from the first 32 bytes of the secret key
    const privateKey = keyPair.secretKey.subarray(0, 32)
    const privateKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
    const publicKeyPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
    pk.set(publicKeyPoint.toBytes())
    return b4a.equals(pk, keyPair.publicKey)
  } catch (e) {
    return false
  }
}

exports.sign = function (message, secretKey) {
  // Dedicated slab for the signature, to avoid retaining unneeded mem and for security
  const signature = b4a.allocUnsafeSlow(64) // Schnorr signature is 64 bytes (32 + 32)

  // Extract the private key from the first 32 bytes of the secret key
  const privateKey = secretKey.subarray(0, 32)

  // Generate random nonce using ristretto255 scalar generation
  const nonceScalar = ristretto255_hasher.hashToScalar(nobleRandomBytes(32))
  const nonce = b4a.from(ristretto255.Point.Fn.toBytes(nonceScalar))

  // Compute R = nonce * G
  const R = ristretto255.Point.BASE.multiply(nonceScalar)
  const R_bytes = b4a.from(R.toBytes())

  // Compute challenge c = H(R || P || message)
  // Derive public key from private key
  const privateKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
  const publicKeyPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
  const publicKey = b4a.from(publicKeyPoint.toBytes())
  
  const challenge = sha256.create()
  challenge.update(R_bytes)
  challenge.update(publicKey)
  challenge.update(message)
  const c = challenge.digest()

  // Compute s = nonce + c * privateKey
  const c_scalar = ristretto255_hasher.hashToScalar(c)
  const privateKey_scalar = ristretto255.Point.Fn.fromBytes(privateKey)
  const s = ristretto255.Point.Fn.add(nonceScalar, ristretto255.Point.Fn.mul(c_scalar, privateKey_scalar))

  // Signature is (R, s)
  signature.set(R_bytes, 0, 32)
  signature.set(b4a.from(ristretto255.Point.Fn.toBytes(s)), 32, 32)

  return signature
}

exports.verify = function (message, signature, publicKey) {
  if (signature.byteLength !== 64) return false
  if (publicKey.byteLength !== 32) return false
  try {
    // Extract R and s from signature
    const R_bytes = signature.subarray(0, 32)
    const s_bytes = signature.subarray(32, 64)

    // Parse points and scalars
    const R = ristretto255.Point.fromBytes(R_bytes)
    const P = ristretto255.Point.fromBytes(publicKey)
    const s = ristretto255.Point.Fn.fromBytes(s_bytes)

    // Compute challenge c = H(R || P || message)
    const challenge = sha256.create()
    challenge.update(R_bytes)
    challenge.update(publicKey)
    challenge.update(message)
    const c = challenge.digest()
    const c_scalar = ristretto255_hasher.hashToScalar(c)

    // Verify: s * G = R + c * P
    const sG = ristretto255.Point.BASE.multiply(s)
    const cP = P.multiply(c_scalar)
    const R_plus_cP = R.add(cP)

    return sG.equals(R_plus_cP)
  } catch (e) {
    return false
  }
}

exports.encrypt = function (message, publicKey) {
  // For ristretto255, we'll use a simple ECIES-like encryption
  // Generate ephemeral key pair
  const ephemeralScalar = ristretto255_hasher.hashToScalar(nobleRandomBytes(32))
  const ephemeralPrivateKey = b4a.from(ristretto255.Point.Fn.toBytes(ephemeralScalar))
  const ephemeralPrivateKeyScalar = ristretto255.Point.Fn.fromBytes(ephemeralPrivateKey)
  const ephemeralPublicKeyPoint = ristretto255.Point.BASE.multiply(ephemeralPrivateKeyScalar)
  const ephemeralPublicKey = b4a.from(ephemeralPublicKeyPoint.toBytes())

  // Derive shared secret using ECDH
  const publicKeyPoint = ristretto255.Point.fromBytes(publicKey)
  const sharedSecretPoint = publicKeyPoint.multiply(ephemeralPrivateKeyScalar)
  const sharedSecret = b4a.from(sharedSecretPoint.toBytes())

  // Use first 32 bytes of shared secret as key for simple XOR encryption
  const key = sharedSecret.subarray(0, 32)

  // Encrypt message with XOR
  const encrypted = b4a.alloc(message.length)
  for (let i = 0; i < message.length; i++) {
    encrypted[i] = message[i] ^ key[i % 32]
  }

  // Return ephemeral public key + encrypted message
  return b4a.concat([ephemeralPublicKey, encrypted])
}

exports.decrypt = function (ciphertext, keyPair) {
  if (ciphertext.byteLength < 32) return null // Need at least ephemeral public key

  const ephemeralPublicKey = ciphertext.subarray(0, 32)
  const encrypted = ciphertext.subarray(32)

  try {
    // Derive shared secret using ECDH
    const ephemeralPublicKeyPoint = ristretto255.Point.fromBytes(ephemeralPublicKey)
    const privateKey = keyPair.secretKey.subarray(0, 32)
    const privateKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
    const sharedSecretPoint = ephemeralPublicKeyPoint.multiply(privateKeyScalar)
    const sharedSecret = b4a.from(sharedSecretPoint.toBytes())

    // Use first 32 bytes of shared secret as key for decryption
    const key = sharedSecret.subarray(0, 32)

    // Decrypt message with XOR
    const plaintext = b4a.alloc(encrypted.length)
    for (let i = 0; i < encrypted.length; i++) {
      plaintext[i] = encrypted[i] ^ key[i % 32]
    }

    return plaintext
  } catch (e) {
    return null
  }
}

exports.encryptionKeyPair = function (seed) {
  let privateKey

  if (seed) {
    // Use seed to generate deterministic private key
    const scalar = ristretto255_hasher.hashToScalar(seed)
    privateKey = b4a.from(ristretto255.Point.Fn.toBytes(scalar))
  } else {
    // Generate random private key using ristretto255 scalar generation
    const scalar = ristretto255_hasher.hashToScalar(nobleRandomBytes(32))
    privateKey = b4a.from(ristretto255.Point.Fn.toBytes(scalar))
  }

  // Derive public key using ristretto255
  const privateKeyScalar = ristretto255.Point.Fn.fromBytes(privateKey)
  const publicKeyPoint = ristretto255.Point.BASE.multiply(privateKeyScalar)
  const publicKey = b4a.from(publicKeyPoint.toBytes())

  return {
    publicKey,
    secretKey: privateKey
  }
}

exports.data = function (data) {
  const out = b4a.allocUnsafe(32)

  const hash = sha256.create()
  hash.update(LEAF_TYPE)
  hash.update(c.encode(c.uint64, data.byteLength))
  hash.update(data)

  const digest = hash.digest()
  out.set(digest)
  return out
}

exports.parent = function (a, b) {
  if (a.index > b.index) {
    const tmp = a
    a = b
    b = tmp
  }

  const out = b4a.allocUnsafe(32)

  const hash = sha256.create()
  hash.update(PARENT_TYPE)
  hash.update(c.encode(c.uint64, a.size + b.size))
  hash.update(a.hash)
  hash.update(b.hash)

  const digest = hash.digest()
  out.set(digest)
  return out
}

exports.tree = function (roots, out) {
  if (!out) out = b4a.allocUnsafe(32)

  const hash = sha256.create()
  hash.update(ROOT_TYPE)

  for (let i = 0; i < roots.length; i++) {
    const r = roots[i]
    hash.update(r.hash)
    hash.update(c.encode(c.uint64, r.index))
    hash.update(c.encode(c.uint64, r.size))
  }

  const digest = hash.digest()
  out.set(digest)
  return out
}

exports.hash = function (data, out) {
  if (!out) out = b4a.allocUnsafe(32)
  if (!Array.isArray(data)) data = [data]

  const hash = sha256.create()
  for (const chunk of data) {
    hash.update(chunk)
  }

  const digest = hash.digest()
  out.set(digest)
  return out
}

exports.randomBytes = function (n) {
  return b4a.from(nobleRandomBytes(n))
}

exports.discoveryKey = function (key) {
  if (!key || key.byteLength !== 32) throw new Error('Must pass a 32 byte buffer')
  // Discovery keys might stay around for a while, so better not to use slab memory (for better gc)
  const digest = b4a.allocUnsafeSlow(32)

  const hash = sha256.create()
  hash.update(HYPERCORE)
  hash.update(key)
  const result = hash.digest()
  digest.set(result)
  return digest
}

exports.free = function () {
  // No-op for @noble/curves as it doesn't use secure memory
}

exports.namespace = function (name, count) {
  const ids = typeof count === 'number' ? range(count) : count

  // Namespaces are long-lived, so better to use a dedicated slab
  const buf = b4a.allocUnsafeSlow(32 * ids.length)

  const list = new Array(ids.length)

  // ns is ephemeral, so default slab
  const ns = b4a.allocUnsafe(33)

  // Hash the name to get the base namespace
  const nameHash = sha256.create()
  nameHash.update(typeof name === 'string' ? b4a.from(name) : name)
  const nameDigest = nameHash.digest()
  ns.set(nameDigest, 0, 32)

  for (let i = 0; i < list.length; i++) {
    list[i] = buf.subarray(32 * i, 32 * i + 32)
    ns[32] = ids[i]

    const itemHash = sha256.create()
    itemHash.update(ns)
    const itemDigest = itemHash.digest()
    list[i].set(itemDigest)
  }

  return list
}

function range (count) {
  const arr = new Array(count)
  for (let i = 0; i < count; i++) arr[i] = i
  return arr
}
