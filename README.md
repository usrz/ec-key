Elliptic Curve Keys
===================

This project defines a wrapper for Elliptic Curve (EC) private and public keys.

* [Curves](#curves);
* [Basic Construction](#basic-construction)
  * [Randomly generated keys](#randomly-generated-keys)
  * [Instantiating from encoded keys](#instantiating-from-encoded-keys)
  * [Instantiating with objects](#instantiating-with-objects)
* [ECKey properties](#eckey-properties)
* [ECKey functions](#eckey-functions)
  * [`asPublicECKey()`](#-aspubliceckey-)
  * [`computeSecret(otherKey)`](#-computesecret-otherkey-)
  * [`createECDH()`](#-createecdh-)
  * [`createSign(hash)`](#-createsign-hash-)
  * [`createVerify(hash)`](#-createverify-hash-)
  * [`toBuffer(format)`](#-tobuffer-format-)
  * [`toString(format)`](#-tostring-format-)
  * [`toJSON()`](#-tojson-)
* [MIT License](LICENSE.md)




Curves
------

This wrapper supports onl the three main curves listed below:

| OpenSSL Curve Name | RFC-7518 (6.2.1.1)      | ASN.1 OID           |
| ------------------ | ----------------------- | ------------------- |
| `prime256v1`       | `P-256`                 | 1.2.840.10045.3.1.7 |
| `secp384k1`        | `P-256K` _non standard_ | 1.3.132.0.10        |
| `secp384r1`        | `P-384`                 | 1.3.132.0.34        |
| `secp521r1`        | `P-521`                 | 1.3.132.0.35        |

Both the OpenSSL names and RFC-7518 (JWA/JWK) names can be used as parameters
to the methods in the `ECKey` class.

Please be aware that _NodeJS_ (and _OpenSSL_) support a large number of curves
(see `openssl ecparam -list_curves` for a full list), but for brevity this
implementation restricts to the three mentioned above.

> *PLEASE NOTE:* The `P-256K` curve name (`crv` parameter) used when serializing
> a key using the `secp384k1` curve is not standard, and *NOT* interoperable
> with other systems.
>
> See the [IANA](https://www.iana.org/assignments/jose/jose.xhtml#web-key-elliptic-curve)
> registry for all known (and interoperable) curve names.
>
> The `P-256K` name used might change at _ANY_ time.


Basic construction
------------------

To use, start importing the main `ECKey` class:

```javascript
const ECKey = require('ec-key');
```


#### Randomly generated keys

To create a random `ECKey` instance simply call the `createECKey` static
method, optionally specifying a curve name (defaults to `prime256v1`):

```javascript
// Create a new (random) ECKey instance using the secp521r1 curve
var randomKey = ECKey.createECKey('P-521');
```


#### Instantiating from encoded keys

To import an existing private or public key, simply invoke the constructor
with a `String` or a `Buffer` and the format in which the key is encoded:

```javascript
// Create a new ECKey instance from a base-64 spki string
var key = new ECKey('MFkwEw ... 3w06qg', 'spki');
```

For `Buffer`s and _base64-encoded_ `String`s the constructor supports both the
`pkcs8` (or `rfc5208`) and `spki` (or `rfc5280`) formats.

Additionally, the `pem` format is supported for _unencoded_ `String`s and
`Buffer`s:

```javascript
// Load up a PEM file and wrap it into a
var pem = fs.readFileSync('./key.pem');
var key = new ECKey(pem, 'pem');
```


#### Instantiating with objects

Instances of the `ECKey` class can also be created from very simple object.

For example JWKs can be used directly, and whereas in the example below the
`crv`, `x` and `y` values will be considered, `kty` and `kid` will be ignored.

```javascript
/// Simply create from a JWK object
var key = new ECKey({
  "kty":"EC",
  "crv":"P-256",
  "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "kid":"Public key used in JWS spec Appendix A.3 example"
})
```

The following values are recognized:

* **`curve`** or **`crv`**: the curve type for this key, identified either by
  its _OpenSSL_ or its _RFC-7518 (JWA/JWK)_ name.

With regards to coordinates:

* **`d`**: the private _d_ coordinate for the elliptic curve point, either as a
  `Buffer`, or a _base64-encoded_ `String` of the coordinate's big endian
  representation
* **`x`**: the public _x_ coordinate for the elliptic curve point, either as a
  `Buffer`, or a _base64-encoded_ `String` of the coordinate's big endian
  representation
* **`y`**: the public _y_ coordinate for the elliptic curve point, either as a
  `Buffer`, or a _base64-encoded_ `String` of the coordinate's big endian
  representation

And also:

* **`publicKey`**: the _uncompressed_ and _prefixed_ (0x04) concatenation of
  the _x_ and _y_ public coordinates' big endian representation, as described
  in [SEC-1 ECC](http://www.secg.org/sec1-v2.pdf) section 2.3.3
* **`privateKey`**: the private _d_ coordinate for the elliptic curve point,
  either as a `Buffer`, or a _base64-encoded_ `String` of the coordinate's big
  endian representation



ECKey properties
----------------

The following _enumerable_ properties are available for instances of `ECKey`:

* **`curve`**: the EC key curve name in _OpenSSL_ format (e.g. `prime256v1`)
* **`isPrivateECKey`**: a _boolean_ indicating whther this instance represents
  a _private_ or _public_ EC key.
* **`x`**: the public _x_ coordinate's big endian representation for the
  elliptic curve point as a `Buffer`
* **`y`**: the public _y_ coordinate's big endian representation for the
  elliptic curve point as a `Buffer`
* **`d`**: the private _d_ coordinate's big endian representation for the
  elliptic curve point as a `Buffer`

Additionally the following properties are available, but not _enumerable_:

* **`jsonCurve`**: the EC key curve name in _RFC-7518_ format (e.g. `P-256`)
* **`publicCodePoint`**: the _uncompressed_ and _prefixed_ (0x04) concatenation of
  the _x_ and _y_ public coordinates' big endian representation, as described
  in [SEC-1 ECC](http://www.secg.org/sec1-v2.pdf) section 2.3.3.



ECKey functions
---------------

#### `asPublicECKey()`

Return `this` instance if this key is a _public_ key, or create a new `ECKey`
instance *not* including the _private_ components of the key.


#### `computeSecret(otherKey)`

A simple shortcut for `createECDH().computeSecret(otherKey)` as explained below.


#### `createECDH()`

Create a standard Node [_ECDH_](https://nodejs.org/api/crypto.html#crypto_class_ecdh)
object instance whose [`computeSecret(...)`](https://nodejs.org/api/crypto.html#crypto_ecdh_computesecret_other_public_key_input_encoding_output_encoding)
function accepts also `ECKey` (as in, this class) instances.


#### `createSign(hash)`

Create a standard Node [_Sign_](https://nodejs.org/api/crypto.html#crypto_class_sign)
object whose [`sign(...)`](https://nodejs.org/api/crypto.html#crypto_sign_sign_private_key_output_format)
function is automatically populated with this instance.

* `hash`: the hashing function to use for generating the signature, normally one
  of `SHA256`, `SHA384` or `SHA512`.

```javascript
// Create a signature of the message "the quick brown fox" with a random key
var message = "the quick brown fox";
var key = ECKey.createECKey('P-384');
var signature = key.createSign('SHA384')
                   .update(message)
                   .sign('base64');
```


#### `createVerify(hash)`

Create a standard Node [_Verify_](https://nodejs.org/api/crypto.html#crypto_class_verify)
object whose [`verify(...)`](https://nodejs.org/api/crypto.html#crypto_verifier_verify_object_signature_signature_format)
function is automatically populated with this instance.

* `hash`: the hashing function to use for generating the signature, normally one
  of `SHA256`, `SHA384` or `SHA512`.

```javascript
// Verify the signature calcuated above
key.createVerify('SHA384')
   .update(message)
   .verify(signature, 'base64');
```

### `toBuffer(format)`

Encode this EC key, optionally using the specified format (defaults to  `pem`).

Formats supported are as follows:

* **`pem`**: return a `Buffer` containing the `ascii` represtation of the
  OpenSSL PEM format
  * equivalent to `new Buffer(key.toString('pem'), 'ascii')` and provided for
    convenience only
* **`rfc5951`**: (_private_ keys only) returns the encoding of this key as
  specified by [RFC-5951](https://tools.ietf.org/html/rfc5951)
* **`pkcs8`** or **`rfc5208`**: (_private_ keys only) returns the PKCS8 encoding
  of this key as specified by [RFC-5208](https://tools.ietf.org/html/rfc5208)
* **`spki`** or **`rfc5280`**: (_public_ keys only) returns the SPKI encoding
  of this key as specified by [RFC-5280](https://tools.ietf.org/html/rfc5280)



### `toString(format)`

Encode this EC key, optionally using the specified format (defaults to  `pem`).

Formats supported are as follows:

* **`pem`**: return the key in OpenSSL's PEM format
* **`rfc5951`**: (_private_ keys only) returns the encoding of this key as
  specified by [RFC-5951](https://tools.ietf.org/html/rfc5951), wrapped with
  a header and footer as outlined in section 4
* **`pkcs8`** or **`rfc5208`**: (_private_ keys only) returns the PKCS8 encoding
  of this key as specified by [RFC-5208](https://tools.ietf.org/html/rfc5208)
  encoded in _base64_
* **`spki`** or **`rfc5280`**: (_public_ keys only) returns the SPKI encoding
  of this key as specified by [RFC-5280](https://tools.ietf.org/html/rfc5280)
  encoded in _base64_



### `toJSON()`

Formats this `ECKey` as a JSON Web Key as specified by
[RFC-7517](https://tools.ietf.org/html/rfc7517).

Please note that his function will also be called by the `JSON.stringify(...)`
function.

```javascript
// Convert a PEM to a JWK in one easy step

var pem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzr+Twxehecu0VYoC
XUBL1Z4h3H28gPnJ5MP0AcOixAOhRANCAAS6pMWMMndZxOPSC9ui6sUUbmeK6dIi
k3ZwTmm0SE7G+tYon5C57aVek5qH4y4OipbSLfbsIQuOkt0G8Vu1KZ3u
-----END PRIVATE KEY-----`;

var key = new ECKey(pem, 'pem');

var jwk = JSON.stringify(key, null, 2);

console.log(jwk);

// This will result in the following output:
// {
//   "kty": "EC",
//   "crv": "P-256",
//   "x": "uqTFjDJ3WcTj0gvbourFFG5niunSIpN2cE5ptEhOxvo",
//   "y": "1iifkLntpV6TmofjLg6KltIt9uwhC46S3QbxW7Upne4",
//   "d": "zr-Twxehecu0VYoCXUBL1Z4h3H28gPnJ5MP0AcOixAM"
// }
```
