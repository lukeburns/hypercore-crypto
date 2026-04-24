const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')
const { ml_dsa44 } = require('@noble/post-quantum/ml-dsa.js')
const { ml_kem512 } = require('@noble/post-quantum/ml-kem.js')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = b4a.from([0])
const PARENT_TYPE = b4a.from([1])
const ROOT_TYPE = b4a.from([2])

const HYPERCORE = b4a.from('hypercore')
const NS_MLDSA = b4a.from('hypercore-crypto/v4/mldsa')
const NS_MLDEM = b4a.from('hypercore-crypto/v4/mldem')
const PQ_SEAL_VERSION = b4a.from([1])

const MLDSA_PUBLICKEYBYTES = ml_dsa44.lengths.publicKey
const MLDSA_SIGNATUREBYTES = ml_dsa44.lengths.signature
const MLDEM_PUBLICKEYBYTES = ml_kem512.lengths.publicKey
const MLDEM_SECRETKEYBYTES = ml_kem512.lengths.secretKey
const MLDEM_CIPHERTEXTBYTES = ml_kem512.lengths.cipherText

/** Wire / manifest label for the only supported batch signature (ML-DSA-44, FIPS 204). */
exports.defaultSignature = 'mldsa44'
exports.defaultHash = 'blake2b'

exports.isSupportedSignature = function (name) {
  return name === exports.defaultSignature
}

exports.keyPair = function (seed) {
  if (!seed) return normalizeNoblePair(ml_dsa44.keygen())
  return exports.mlDsaKeyPair(seed)
}

exports.validateKeyPair = function (keyPair) {
  const publicKey = b4a.from(ml_dsa44.getPublicKey(keyPair.secretKey))
  return b4a.equals(publicKey, keyPair.publicKey)
}

exports.sign = function (message, secretKey) {
  return b4a.from(ml_dsa44.sign(message, secretKey, { extraEntropy: false }))
}

exports.verify = function (message, signature, publicKey) {
  if (signature.byteLength !== MLDSA_SIGNATUREBYTES) return false
  if (publicKey.byteLength !== MLDSA_PUBLICKEYBYTES) return false
  return ml_dsa44.verify(signature, message, publicKey)
}

exports.encrypt = function (message, publicKey) {
  if (publicKey.byteLength !== MLDEM_PUBLICKEYBYTES) {
    throw new Error(
      'ML-KEM-512 public key required (expected ' + MLDEM_PUBLICKEYBYTES + ' bytes, got ' + publicKey.byteLength + ')'
    )
  }

  const nonce = b4a.allocUnsafe(sodium.crypto_secretbox_NONCEBYTES)
  sodium.randombytes_buf(nonce)

  const { cipherText, sharedSecret } = ml_kem512.encapsulate(publicKey)
  const box = b4a.allocUnsafe(message.byteLength + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(box, message, nonce, sharedSecret)

  const ciphertext = b4a.concat([PQ_SEAL_VERSION, b4a.from(cipherText), nonce, box])
  b4a.fill(sharedSecret, 0)
  return ciphertext
}

exports.decrypt = function (ciphertext, keyPair) {
  if (!ciphertext || ciphertext.byteLength === 0) return null
  if (ciphertext[0] !== PQ_SEAL_VERSION[0]) return null
  if (keyPair.secretKey.byteLength !== MLDEM_SECRETKEYBYTES) return null

  const header = 1 + MLDEM_CIPHERTEXTBYTES + sodium.crypto_secretbox_NONCEBYTES
  if (ciphertext.byteLength < header + sodium.crypto_secretbox_MACBYTES) return null

  let offset = 1
  const kemCiphertext = ciphertext.subarray(offset, offset + MLDEM_CIPHERTEXTBYTES)
  offset += MLDEM_CIPHERTEXTBYTES

  const nonce = ciphertext.subarray(offset, offset + sodium.crypto_secretbox_NONCEBYTES)
  offset += sodium.crypto_secretbox_NONCEBYTES

  const box = ciphertext.subarray(offset)
  if (box.byteLength < sodium.crypto_secretbox_MACBYTES) return null

  const plaintext = b4a.allocUnsafe(box.byteLength - sodium.crypto_secretbox_MACBYTES)
  const sharedSecret = b4a.from(ml_kem512.decapsulate(kemCiphertext, keyPair.secretKey))

  const ok = sodium.crypto_secretbox_open_easy(plaintext, box, nonce, sharedSecret)
  b4a.fill(sharedSecret, 0)

  if (!ok) return null
  return plaintext
}

exports.encryptionKeyPair = function (seed) {
  if (!seed) return normalizeNoblePair(ml_kem512.keygen())
  return exports.mlDemKeyPair(seed)
}

exports.kdf = function (primaryKey, namespace, length = 32) {
  if (!primaryKey || primaryKey.byteLength === 0) throw new Error('Must pass a primaryKey buffer')
  const ns = typeof namespace === 'string' ? b4a.from(namespace) : namespace
  if (!ns || ns.byteLength === 0) throw new Error('Must pass a namespace buffer')
  if (!(length > 0)) throw new Error('length must be > 0')

  const out = b4a.allocUnsafe(length)
  sodium.crypto_generichash_batch(out, [ns, primaryKey])
  return out
}

exports.mlDsaKeyPair = function (primaryKey, namespace = NS_MLDSA) {
  const seed = exports.kdf(primaryKey, namespace, ml_dsa44.lengths.seed)
  const pair = normalizeNoblePair(ml_dsa44.keygen(seed))
  b4a.fill(seed, 0)
  return pair
}

exports.mlDemKeyPair = function (primaryKey, namespace = NS_MLDEM) {
  const seed = exports.kdf(primaryKey, namespace, ml_kem512.lengths.seed)
  const pair = normalizeNoblePair(ml_kem512.keygen(seed))
  b4a.fill(seed, 0)
  return pair
}

exports.data = function (data) {
  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [LEAF_TYPE, c.encode(c.uint64, data.byteLength), data])

  return out
}

exports.parent = function (a, b) {
  if (a.index > b.index) {
    const tmp = a
    a = b
    b = tmp
  }

  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    PARENT_TYPE,
    c.encode(c.uint64, a.size + b.size),
    a.hash,
    b.hash
  ])

  return out
}

exports.tree = function (roots, out) {
  const buffers = new Array(3 * roots.length + 1)
  let j = 0

  buffers[j++] = ROOT_TYPE

  for (let i = 0; i < roots.length; i++) {
    const r = roots[i]
    buffers[j++] = r.hash
    buffers[j++] = c.encode(c.uint64, r.index)
    buffers[j++] = c.encode(c.uint64, r.size)
  }

  if (!out) out = b4a.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, buffers)
  return out
}

exports.hash = function (data, out) {
  if (!out) out = b4a.allocUnsafe(32)
  if (!Array.isArray(data)) data = [data]

  sodium.crypto_generichash_batch(out, data)

  return out
}

exports.randomBytes = function (n) {
  const buf = b4a.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (key) {
  if (!key || key.byteLength === 0) throw new Error('Must pass a non-empty key buffer')
  // Discovery keys might stay around for a while, so better not to use slab memory (for better gc)
  const digest = b4a.allocUnsafeSlow(32)
  sodium.crypto_generichash_batch(digest, [HYPERCORE, key])
  return digest
}

if (sodium.sodium_free) {
  exports.free = function (secureBuf) {
    if (secureBuf.secure) sodium.sodium_free(secureBuf)
  }
} else {
  exports.free = function () {}
}

exports.namespace = function (name, count) {
  const ids = typeof count === 'number' ? range(count) : count

  // Namespaces are long-lived, so better to use a dedicated slab
  const buf = b4a.allocUnsafeSlow(32 * ids.length)

  const list = new Array(ids.length)

  // ns is ephemeral, so default slab
  const ns = b4a.allocUnsafe(33)
  sodium.crypto_generichash(ns.subarray(0, 32), typeof name === 'string' ? b4a.from(name) : name)

  for (let i = 0; i < list.length; i++) {
    list[i] = buf.subarray(32 * i, 32 * i + 32)
    ns[32] = ids[i]
    sodium.crypto_generichash(list[i], ns)
  }

  return list
}

function range(count) {
  const arr = new Array(count)
  for (let i = 0; i < count; i++) arr[i] = i
  return arr
}

function normalizeNoblePair(pair) {
  return {
    publicKey: b4a.from(pair.publicKey),
    secretKey: b4a.from(pair.secretKey)
  }
}
