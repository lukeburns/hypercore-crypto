const test = require('brittle')
const b4a = require('b4a')
const crypto = require('./')
const sodium = require('sodium-universal')
const { ml_dsa44 } = require('@noble/post-quantum/ml-dsa.js')
const { ml_kem512 } = require('@noble/post-quantum/ml-kem.js')

test('randomBytes', function (t) {
  const buffer = crypto.randomBytes(100)
  t.ok(b4a.isBuffer(buffer))
  t.unlike(crypto.randomBytes(100), buffer)
})

test('key pair', function (t) {
  const keyPair = crypto.keyPair()

  t.is(keyPair.publicKey.length, ml_dsa44.lengths.publicKey)
  t.is(keyPair.secretKey.length, ml_dsa44.lengths.secretKey)
})

test('validate key pair', function (t) {
  const keyPair1 = crypto.keyPair()
  const keyPair2 = crypto.keyPair()

  t.absent(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair2.secretKey }))
  t.ok(crypto.validateKeyPair({ publicKey: keyPair1.publicKey, secretKey: keyPair1.secretKey }))
})

test('sign', function (t) {
  const keyPair = crypto.keyPair()
  const message = b4a.from('hello world')

  const sig = crypto.sign(message, keyPair.secretKey)

  t.is(sig.length, ml_dsa44.lengths.signature)
  t.ok(crypto.verify(message, sig, keyPair.publicKey))
  t.absent(crypto.verify(message, b4a.alloc(ml_dsa44.lengths.signature - 1), keyPair.publicKey))
})

test('encryption key pair', function (t) {
  const primaryKey = crypto.randomBytes(32)
  const kp1 = crypto.encryptionKeyPair(primaryKey)
  const kp2 = crypto.encryptionKeyPair(primaryKey)
  const kp3 = crypto.encryptionKeyPair(crypto.randomBytes(32))

  t.is(kp1.publicKey.length, ml_kem512.lengths.publicKey)
  t.is(kp1.secretKey.length, ml_kem512.lengths.secretKey)
  t.alike(kp1, kp2)
  t.unlike(kp1.publicKey, kp3.publicKey)
})

test('encrypt/decrypt roundtrip (pq)', function (t) {
  const pair = crypto.encryptionKeyPair()
  const message = b4a.from('pq ciphertext payload')
  const ciphertext = crypto.encrypt(message, pair.publicKey)
  const plaintext = crypto.decrypt(ciphertext, pair)

  t.unlike(ciphertext, message)
  t.alike(plaintext, message)
})

test('encrypt rejects non-ML-KEM public keys', function (t) {
  t.exception(function () {
    crypto.encrypt(b4a.from('x'), b4a.alloc(32))
  }, /ML-KEM-512 public key required/)
})

test('default signature and hash labels', function (t) {
  t.is(crypto.defaultSignature, 'mldsa44')
  t.is(crypto.defaultHash, 'blake2b')
  t.ok(crypto.isSupportedSignature('mldsa44'))
  t.absent(crypto.isSupportedSignature('ed25519'))
})

test('decrypt returns null for wrong key pair', function (t) {
  const senderTarget = crypto.encryptionKeyPair()
  const wrong = crypto.encryptionKeyPair()
  const message = b4a.from('wrong key should fail')
  const ciphertext = crypto.encrypt(message, senderTarget.publicKey)

  t.is(crypto.decrypt(ciphertext, wrong), null)
})

test('kdf deterministic + namespace separated', function (t) {
  const primaryKey = b4a.from('deterministic-primary-key-material')
  const nsA1 = crypto.kdf(primaryKey, b4a.from('app/ns-a'))
  const nsA2 = crypto.kdf(primaryKey, b4a.from('app/ns-a'))
  const nsB = crypto.kdf(primaryKey, b4a.from('app/ns-b'))

  t.alike(nsA1, nsA2)
  t.unlike(nsA1, nsB)
})

test('ml dsa key derivation deterministic + namespace separated', function (t) {
  const primaryKey = crypto.randomBytes(32)
  const keyPairA1 = crypto.mlDsaKeyPair(primaryKey, b4a.from('dsa/ns-a'))
  const keyPairA2 = crypto.mlDsaKeyPair(primaryKey, b4a.from('dsa/ns-a'))
  const keyPairB = crypto.mlDsaKeyPair(primaryKey, b4a.from('dsa/ns-b'))

  t.alike(keyPairA1, keyPairA2)
  t.unlike(keyPairA1.publicKey, keyPairB.publicKey)
  t.unlike(keyPairA1.secretKey, keyPairB.secretKey)
  t.ok(crypto.validateKeyPair(keyPairA1))
})

test('ml dem key derivation deterministic + namespace separated', function (t) {
  const primaryKey = crypto.randomBytes(32)
  const keyPairA1 = crypto.mlDemKeyPair(primaryKey, b4a.from('dem/ns-a'))
  const keyPairA2 = crypto.mlDemKeyPair(primaryKey, b4a.from('dem/ns-a'))
  const keyPairB = crypto.mlDemKeyPair(primaryKey, b4a.from('dem/ns-b'))

  t.alike(keyPairA1, keyPairA2)
  t.unlike(keyPairA1.publicKey, keyPairB.publicKey)
  t.unlike(keyPairA1.secretKey, keyPairB.secretKey)
  t.is(keyPairA1.publicKey.length, ml_kem512.lengths.publicKey)
  t.is(keyPairA1.secretKey.length, ml_kem512.lengths.secretKey)
})

test('hash leaf', function (t) {
  const data = b4a.from('hello world')

  t.alike(
    crypto.data(data),
    b4a.from('9f1b578fd57a4df015493d2886aec9600eef913c3bb009768c7f0fb875996308', 'hex')
  )
})

test('hash parent', function (t) {
  const data = b4a.from('hello world')

  const parent = crypto.parent(
    {
      index: 0,
      size: 11,
      hash: crypto.data(data)
    },
    {
      index: 2,
      size: 11,
      hash: crypto.data(data)
    }
  )

  t.alike(
    parent,
    b4a.from('3ad0c9b58b771d1b7707e1430f37c23a23dd46e0c7c3ab9c16f79d25f7c36804', 'hex')
  )
})

test('tree', function (t) {
  const roots = [
    { index: 3, size: 11, hash: b4a.alloc(32) },
    { index: 9, size: 2, hash: b4a.alloc(32) }
  ]

  t.alike(
    crypto.tree(roots),
    b4a.from('0e576a56b478cddb6ffebab8c494532b6de009466b2e9f7af9143fc54b9eaa36', 'hex')
  )
})

test('hash', function (t) {
  const hash1 = b4a.allocUnsafe(32)
  const hash2 = b4a.allocUnsafe(32)
  const hash3 = b4a.allocUnsafe(32)

  const input = [b4a.alloc(24, 0x3), b4a.alloc(12, 0x63)]

  sodium.crypto_generichash(hash1, b4a.concat(input))
  sodium.crypto_generichash_batch(hash2, input)
  crypto.hash(input, hash3)

  t.alike(hash2, hash1)
  t.alike(hash3, hash1)
  t.alike(crypto.hash(input), hash1)
  t.alike(crypto.hash(b4a.concat(input)), hash1)
})

test('namespace', function (t) {
  const ns = crypto.namespace('hyperswarm/secret-stream', 2)

  t.alike(
    ns[0],
    b4a.from('a931a0155b5c09e6d28628236af83c4b8a6af9af60986edeede9dc5d63192bf7', 'hex')
  )
  t.alike(
    ns[1],
    b4a.from('742c9d833d430af4c48a8705e91631eecf295442bbca18996e597097723b1061', 'hex')
  )
  t.is(ns[0].buffer.byteLength < 1000, true, 'no default slab')
  t.is(ns[0].buffer, ns[1].buffer, 'slab shared between entries')
})

test('namespace (random access)', function (t) {
  const ns = crypto.namespace('hyperswarm/secret-stream', [1, 0])

  t.alike(
    ns[0],
    b4a.from('742c9d833d430af4c48a8705e91631eecf295442bbca18996e597097723b1061', 'hex')
  )
  t.alike(
    ns[1],
    b4a.from('a931a0155b5c09e6d28628236af83c4b8a6af9af60986edeede9dc5d63192bf7', 'hex')
  )
})

test('another namespace', function (t) {
  const ns = crypto.namespace('foo', [1])

  t.alike(
    ns[0],
    b4a.from('fff5eac99641b1b9dee6cabaaeb5959f4b452f7c83769156566aa44de89c82fb', 'hex')
  )
})

test('random namespace', function (t) {
  const s = Math.random().toString()
  const ns1 = crypto.namespace(s, 10).slice(1)
  const ns2 = crypto.namespace(s, [1, 2, 3, 4, 5, 6, 7, 8, 9])

  t.alike(ns1, ns2)
})

test('discovery key does not use slabs', function (t) {
  const key = crypto.keyPair().publicKey
  const discKey = crypto.discoveryKey(key)
  t.is(discKey.buffer.byteLength, 32, 'does not use slab memory')
})
