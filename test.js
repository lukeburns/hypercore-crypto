const test = require('brittle')
const b4a = require('b4a')
const crypto = require('./')

test('randomBytes', function (t) {
  const buffer = crypto.randomBytes(100)
  t.ok(b4a.isBuffer(buffer))
  t.unlike(crypto.randomBytes(100), buffer)
})

test('key pair', function (t) {
  const keyPair = crypto.keyPair()

  t.is(keyPair.publicKey.length, 32)
  t.is(keyPair.secretKey.length, 64)
  t.is(keyPair.publicKey.buffer.byteLength, 96, 'small slab')
  t.is(keyPair.publicKey.buffer, keyPair.secretKey.buffer, 'public and seret key share the same slab')
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

  t.is(sig.length, 64)
  t.ok(crypto.verify(message, sig, keyPair.publicKey))
  t.absent(crypto.verify(message, b4a.alloc(64), keyPair.publicKey))
  t.is(sig.buffer.byteLength, 64, 'dedicated slab for signatures')
})

test('hash leaf', function (t) {
  const data = b4a.from('hello world')

  t.alike(crypto.data(data), b4a.from('bc260f875f75e760bd05e029648785cc3793100eda763cf9754423442027bcb5', 'hex'))
})

test('hash parent', function (t) {
  const data = b4a.from('hello world')

  const parent = crypto.parent({
    index: 0,
    size: 11,
    hash: crypto.data(data)
  }, {
    index: 2,
    size: 11,
    hash: crypto.data(data)
  })

  t.alike(parent, b4a.from('4833ade2953f91bed18adc4dd0b23998126d7b85dfbb74ee8b3bdff5fdb2f12e', 'hex'))
})

test('tree', function (t) {
  const roots = [
    { index: 3, size: 11, hash: b4a.alloc(32) },
    { index: 9, size: 2, hash: b4a.alloc(32) }
  ]

  t.alike(crypto.tree(roots), b4a.from('cdda7cb78b06d51e3eb0d8d07fc4e1e2150d633529f57fb130a2b624b5991c63', 'hex'))
})

test('hash', function (t) {
  const hash1 = b4a.allocUnsafe(32)
  const hash2 = b4a.allocUnsafe(32)
  const hash3 = b4a.allocUnsafe(32)

  const input = [b4a.alloc(24, 0x3), b4a.alloc(12, 0x63)]

  // Test that our hash function works consistently
  crypto.hash(b4a.concat(input), hash1)
  crypto.hash(input, hash2)
  crypto.hash(input, hash3)

  t.alike(hash2, hash1)
  t.alike(hash3, hash1)
  t.alike(crypto.hash(input), hash1)
  t.alike(crypto.hash(b4a.concat(input)), hash1)
})

test('namespace', function (t) {
  const ns = crypto.namespace('hyperswarm/secret-stream', 2)

  t.alike(ns[0], b4a.from('138928bc4460aef85413a5582cc52b6e3350dd647e59c4188c365efeec5a6767', 'hex'))
  t.alike(ns[1], b4a.from('917887fe6bc70bf11920ca7fe6275835748ce3a7ad7bbc4fec985d548a2329ea', 'hex'))
  t.is(ns[0].buffer.byteLength < 1000, true, 'no default slab')
  t.is(ns[0].buffer, ns[1].buffer, 'slab shared between entries')
})

test('namespace (random access)', function (t) {
  const ns = crypto.namespace('hyperswarm/secret-stream', [1, 0])

  t.alike(ns[0], b4a.from('917887fe6bc70bf11920ca7fe6275835748ce3a7ad7bbc4fec985d548a2329ea', 'hex'))
  t.alike(ns[1], b4a.from('138928bc4460aef85413a5582cc52b6e3350dd647e59c4188c365efeec5a6767', 'hex'))
})

test('another namespace', function (t) {
  const ns = crypto.namespace('foo', [1])

  t.alike(ns[0], b4a.from('07bfc109a2e784a10a854cff89f4d5ae745aee1c9048d5eed255784a9ea3f7d0', 'hex'))
})

test('random namespace', function (t) {
  const s = Math.random().toString()
  const ns1 = crypto.namespace(s, 10).slice(1)
  const ns2 = crypto.namespace(s, [1, 2, 3, 4, 5, 6, 7, 8, 9])

  t.alike(ns1, ns2)
})

test('discovery key does not use slabs', function (t) {
  const key = b4a.allocUnsafe(32)
  const discKey = crypto.discoveryKey(key)
  t.is(discKey.buffer.byteLength, 32, 'does not use slab memory')
})
