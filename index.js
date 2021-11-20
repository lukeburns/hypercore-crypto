const sodium = require('sodium-universal')
const c = require('compact-encoding')
const b4a = require('b4a')

// https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack
const LEAF_TYPE = b4a.from([0])
const PARENT_TYPE = b4a.from([1])
const ROOT_TYPE = b4a.from([2])

const HYPERCORE = b4a.from('hypercore')

exports.keyPair = function (secretKey) {
  if (!secretKey) {
    secretKey = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
    sodium.crypto_core_ristretto255_scalar_random(secretKey)
  }

  const publicKey = b4a.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_scalarmult_ristretto255_base(publicKey, secretKey)

  return {
    publicKey,
    secretKey
  }
}

exports.validateKeyPair = function (keyPair) {
  const pk = b4a.allocUnsafe(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_scalarmult_ristretto255_base(pk, keyPair.secretKey)
  return pk.equals(keyPair.publicKey)
}

exports.sign = function (m, sk) {
  if (typeof m === 'string') m = b4a.from(m)
  if (typeof sk === 'string') sk = b4a.from(sk, 'hex')
  const k = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const eBytes = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const e = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const xe = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const s = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const r = b4a.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_core_ristretto255_scalar_random(k) // k
  sodium.crypto_scalarmult_ristretto255_base(r, k) // r = k*g
  sodium.crypto_generichash(eBytes, b4a.concat([r, m])) // e = hash(r|m)
  bytesToScalar(e, eBytes)
  sodium.crypto_core_ristretto255_scalar_mul(xe, sk, e) // xe = e*sk
  sodium.crypto_core_ristretto255_scalar_sub(s, k, xe) // s = k - esk
  return b4a.concat([s, e]) // sig = (s,e)
}

exports.verify = function (m, sig, pk) {
  if (typeof m === 'string') m = b4a.from(m)
  if (typeof sig === 'string') sig = b4a.from(sig, 'hex')
  if (typeof pk === 'string') pk = b4a.from(pk, 'hex')
  const s = sig.slice(0, sodium.crypto_core_ristretto255_SCALARBYTES)
  const e = sig.slice(sodium.crypto_core_ristretto255_SCALARBYTES, 2 * sodium.crypto_core_ristretto255_SCALARBYTES)
  const evBytes = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const ev = b4a.alloc(sodium.crypto_core_ristretto255_SCALARBYTES)
  const sg = b4a.alloc(sodium.crypto_core_ristretto255_BYTES)
  const epk = b4a.alloc(sodium.crypto_core_ristretto255_BYTES)
  const rv = b4a.alloc(sodium.crypto_core_ristretto255_BYTES)
  sodium.crypto_scalarmult_ristretto255_base(sg, s) // sg = s*g
  sodium.crypto_scalarmult_ristretto255(epk, e, pk) // epk = e*pk
  sodium.crypto_core_ristretto255_add(rv, sg, epk) // rv = sg + epk = (k - e sk)g + epk = k g - e pk + e pk = k g
  sodium.crypto_generichash(evBytes, b4a.concat([rv, m])) // e = hash(r|m)c
  bytesToScalar(ev, evBytes)
  return ev.equals(e)
}

exports.data = function (data) {
  const out = b4a.allocUnsafe(32)

  sodium.crypto_generichash_batch(out, [
    LEAF_TYPE,
    c.encode(c.uint64, data.byteLength),
    data
  ])

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

exports.randomBytes = function (n) {
  const buf = b4a.allocUnsafe(n)
  sodium.randombytes_buf(buf)
  return buf
}

exports.discoveryKey = function (publicKey) {
  const digest = b4a.allocUnsafe(32)
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

function bytesToScalar (buf, bytes) {
  sodium.crypto_core_ristretto255_scalar_mul(buf, one, bytes)
}
