const sodium = require('sodium-native')
const uint64be = require('uint64be')

const one = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
one.fill(0)
one[0] = 1

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = Buffer.from([0])
const PARENT_TYPE = Buffer.from([1])
const ROOT_TYPE = Buffer.from([2])
const CAP_TYPE = Buffer.from([3])

const HYPERCORE = Buffer.from('hypercore')
const HYPERCORE_CAP = Buffer.from('hypercore capability')

exports.writerCapability = function (key, secretKey, split) {
  if (!split) return null

  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    CAP_TYPE,
    HYPERCORE_CAP,
    split.tx.slice(0, 32),
    key
  ], split.rx.slice(0, 32))

  return exports.sign(out, secretKey)
}

exports.verifyRemoteWriterCapability = function (key, cap, split) {
  if (!split) return null

  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    CAP_TYPE,
    HYPERCORE_CAP,
    split.rx.slice(0, 32),
    key
  ], split.tx.slice(0, 32))

  return exports.verify(out, cap, key)
}

// TODO: add in the CAP_TYPE in a future version
exports.capability = function (key, split) {
  if (!split) return null

  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    HYPERCORE_CAP,
    split.tx.slice(0, 32),
    key
  ], split.rx.slice(0, 32))

  return out
}

// TODO: add in the CAP_TYPE in a future version
exports.remoteCapability = function (key, split) {
  if (!split) return null

  const out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, [
    HYPERCORE_CAP,
    split.rx.slice(0, 32),
    key
  ], split.tx.slice(0, 32))

  return out
}

exports.keyPair = function () {
  const sk = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const pk = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_core_ristretto255_scalar_random(sk)
  sodium.crypto_scalarmult_ristretto255_base(pk, sk)
  return {
    publicKey: pk,
    secretKey: sk
  }
}

exports.sign = function (m, sk) {
  if (typeof m === 'string') m = Buffer.from(m)
  if (typeof sk === 'string') sk = Buffer.from(sk, 'hex')
  const k = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const eBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const e = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const xe = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const s = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const r = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_core_ristretto255_scalar_random(k) // k
  sodium.crypto_scalarmult_ristretto255_base(r, k) // r = k*g
  sodium.crypto_generichash(eBytes, Buffer.concat([r, m])) // e = hash(r|m)
  bytesToScalar(e, eBytes)
  sodium.crypto_core_ristretto255_scalar_mul(xe, sk, e) // xe = e*sk
  sodium.crypto_core_ristretto255_scalar_sub(s, k, xe) // s = k - esk
  return Buffer.concat([s, e]) // sig = (s,e)
}

exports.verify = function (m, sig, pk) {
  if (typeof m === 'string') m = Buffer.from(m)
  if (typeof sig === 'string') sig = Buffer.from(sig, 'hex')
  if (typeof pk === 'string') pk = Buffer.from(pk, 'hex')
  const s = sig.slice(0, sodium.crypto_core_ristretto255_SCALARBYTES)
  const e = sig.slice(sodium.crypto_core_ristretto255_SCALARBYTES, 2 * sodium.crypto_core_ristretto255_SCALARBYTES)
  const evBytes = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const ev = Buffer.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const sg = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  const epk = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  const rv = Buffer.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_scalarmult_ristretto255_base(sg, s) // sg = s*g
  sodium.crypto_scalarmult_ristretto255(epk, e, pk) // epk = e*pk
  sodium.crypto_core_ristretto255_add(rv, sg, epk) // rv = sg + epk = (k - e sk)g + epk = k g - e pk + e pk = k g
  sodium.crypto_generichash(evBytes, Buffer.concat([rv, m])) // e = hash(r|m)c
  bytesToScalar(ev, evBytes)
  return ev.equals(e)
}

exports.data = function (data) {
  const out = Buffer.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    LEAF_TYPE,
    encodeUInt64(data.length),
    data
  ])

  return out
}

exports.leaf = function (leaf) {
  return exports.data(leaf.data)
}

exports.parent = function (a, b) {
  if (a.index > b.index) {
    const tmp = a
    a = b
    b = tmp
  }

  const out = Buffer.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    PARENT_TYPE,
    encodeUInt64(a.size + b.size),
    a.hash,
    b.hash
  ])

  return out
}

exports.tree = function (roots, out) {
  const buffers = new Array(3 * roots.length + 1)
  var j = 0

  buffers[j++] = ROOT_TYPE

  for (var i = 0; i < roots.length; i++) {
    const r = roots[i]
    buffers[j++] = r.hash
    buffers[j++] = encodeUInt64(r.index)
    buffers[j++] = encodeUInt64(r.size)
  }

  if (!out) out = Buffer.allocUnsafe(32)
  sodium.crypto_generichash_batch(out, buffers)
  return out
}

exports.signable = function (roots, length) {
  const out = Buffer.allocUnsafe(40)

  if (Buffer.isBuffer(roots)) roots.copy(out)
  else exports.tree(roots, out.slice(0, 32))

  uint64be.encode(length, out.slice(32))

  return out
}

exports.randomBytes = function (n) {
  const buf = Buffer.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (publicKey) {
  const digest = Buffer.allocUnsafe(32)
  sodium.crypto_generichash(digest, HYPERCORE, publicKey)
  return digest
}

if (sodium.sodium_free) {
  exports.free = function (secureBuf) {
    if (secureBuf.secure) sodium.sodium_free(secureBuf)
  }
} else {
  exports.free = function () {}
}

function encodeUInt64 (n) {
  return uint64be.encode(n, Buffer.allocUnsafe(8))
}

function bytesToScalar (buf, bytes) {
  sodium.crypto_core_ristretto255_scalar_mul(buf, one, bytes)
}
