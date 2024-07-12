import type { ECDH, Sign, Verify } from 'node:crypto'

type jsonCurveName = 'P-256' | 'P-256K' | 'P-384' | 'P-521'
type curveName = 'prime256v1'| 'secp256k1' | 'secp384r1' | 'secp521r1'
type inputFormat = 'pem' | 'pkcs8' | 'rfc5208' | 'spki' | 'rfc5280'
type outputFormat = 'pem' | 'pkcs8' | 'rfc5208' | 'spki' | 'rfc5280' | 'rfc5951'

interface ECKeyOptions {
  /** The OpenSSL curve name of the `ECKey` to create */
  curve?: curveName,
  /** The RFC-7518 (JWA/JWK) curve name of the `ECKey` to create */
  crv?: jsonCurveName,

  /** The private `d` coordinate's big endian representation */
  privateKey?: string | Buffer,
  /**
   * The uncompressed and prefixed (`0x04`) concatenation of the `x` and `y`
   * public coordinates' big endian representation
   */
  publicKey?: string | Buffer,

  /**
   * The private `d` coordinate for the elliptic curve point, either as a Buffer
   * or a base64-encoded string of the coordinate's big endian representation
   */
  d?: string | Buffer,
  /**
   * The public `x` coordinate for the elliptic curve point, either as a Buffer
   * or a base64-encoded string of the coordinate's big endian representation
   */
  x?: string | Buffer,
  /**
   * The public `y` coordinate for the elliptic curve point, either as a Buffer
   * or a base64-encoded string of the coordinate's big endian representation
   */
  y?: string | Buffer,
}

declare class ECKey {
  /** Create a new `ECKey` instance parsing the specified key in the default `PEM` format */
  constructor(key: string | Buffer)
  /** Create a new `ECKey` instance parsing the specified key using the specified format */
  constructor(key: string | Buffer, format: inputFormat)
  /** Create a new `ECKey` instance from the specified options */
  constructor(options: ECKeyOptions)

  /** Create a new (random) `ECKey` instance using the default `prime256v1` curve */
  static createECKey(): ECKey
  /** Create a new (random) `ECKey` instance using the specified curve */
  static createECKey(curve: curveName | jsonCurveName): ECKey

  /** The EC key curve name in OpenSSL format (e.g. prime256v1) */
  curve: curveName
  /** A boolean indicating whther this instance represents a private or public EC key. */
  isPrivateECKey: boolean
  /* The public `x` coordinate's big endian representation for the elliptic curve point as a Buffer */
  x: Buffer
  /* The public `y` coordinate's big endian representation for the elliptic curve point as a Buffer */
  y: Buffer
  /* The private `d` coordinate's big endian representation for the elliptic curve point as a Buffer */
  d?: Buffer

  /** The EC key curve name in RFC-7518 format (e.g. P-256) */
  jsonCurve: jsonCurveName
  /**
   * The uncompressed and prefixed (0x04) concatenation of the x and y public
   * coordinates' big endian representation, as described in SEC-1 ECC section 2.3.3.
   */
  publicCodePoint: Buffer

  /**
   * Return this instance if this key is a public key, or create a new `ECKey`
   * instance not including the private components of the key.
   */
  asPublicECKey(): ECKey

  /** A simple shortcut for `createECDH().computeSecret(otherKey)`. */
  computeSecret(otherKey: ECKey | NodeJS.ArrayBufferView): Buffer

  /**
   * Create a standard Node `ECDH` object instance whose `computeSecret(...)`
   * function accepts also ECKey (as in, this class) instances.
   */
  createECDH(): ECDH & {
    computeSecret(key: ECKey): Buffer
  }

  /**
   * Create a standard Node `Sign` object whose `sign(...)` function is
   * automatically populated with this instance.
   */
  createSign(hash: string): Sign

  /**
   * Create a standard Node `Verify` object whose `verify(...)` function is
   * automatically populated with this instance.
   */
  createVerify(hash: string): Verify

  /** Encode this `ECKey`, optionally using the specified format (defaults to `pem`). */
  toBuffer(format?: outputFormat): Buffer
  /** Encode this `ECKey`, optionally using the specified format (defaults to `pem`). */
  toString(format?: outputFormat): string
  /** Formats this ECKey as a JSON Web Key as specified by RFC-7517. */
  toJSON(): {
    kty: "EC",
    crv: jsonCurveName,
    x: string,
    y: string,
    d: string,
  }
}

export default ECKey
