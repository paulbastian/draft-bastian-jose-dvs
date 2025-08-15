---
title: "Designated Verifier Signatures for JOSE"
abbrev: "DVS for JOSE"
category: info

docname: draft-bastian-jose-dvs-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Javascript Object Signing and Encryption"
keyword:
 - JOSE
 - JWS
 - designated verifier signature
 - HPKE
venue:
  group: "Javascript Object Signing and Encryption"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  github: "paulbastian/draft-bastian-jose-dvs"
  latest: "https://paulbastian.github.io/draft-bastian-jose-dvs/draft-bastian-jose-dvs.html"

author:
 -
    fullname: Paul Bastian
    email: bastianpaul@googlemail.com

 -
    fullname: Micha Kraus
    email: kraus.micha@gmail.com

normative:
  RFC7515: RFC7515
  RFC7517: RFC7517
  RFC7518: RFC7518
  RFC9180: RFC9180
  RFC5869: RFC5869
  RFC2104: RFC2104
  BSI-TR-03111:
    title: "Technical Guideline BSI TR-03111: Elliptic Curve Cryptography, Version 2.10"
    target: https://www.bsi.bund.de/dok/TR-03111-en
    date: June 2018


informative:
  HPKE-IANA:
    title: Hybrid Public Key Encryption (HPKE) IANA Registry
    target: https://www.iana.org/assignments/hpke/hpke.xhtml
    date: October 2023
  ISO-18013-5:
    title: "ISO/IEC 18013-5:2021, Personal identification — ISO-compliant driving licence, Part 5: Mobile driving licence (mDL) application"
    target: https://www.iso.org/standard/69084.html
    date: September 2021
  TLS-NOTARY:
    title: "TLSNotary project"
    target: https://tlsnotary.org/
    date: October 2024




--- abstract

This specification describes how to use a Diffie-Hellman key agreement (DH-KA) protocol and a key derivation function (KDF) to derive a symmetric Message Authentication Code (MAC) key using information conveyed within a JSON Web Signature (JWS).

--- middle

# Introduction

JSON Web Signature (JWS) [RFC 7515] and JSON Web Algorithms (JWA) [RFC 7518] specify how to secure content with Hash-based Message Authentication Codes (HMAC) [RFC 2104] using a shared symmetric key. These specifications do not provide means to dynamically derive a MAC key for JWS validation using only public information embedded in the JWS. 

This specification defines a new protected header parameter, `pkds` (public key derived secret), which contains information required to derive an HMAC key using a Diffie-Hellman key agreement (DH-KA) and a key derivation function (KDF). The JWS Producer's DH-KA public key appears either in the `pkds` parameter or in a claims element for use in the key agreement computation. The `pkds` parameter also includes the JWS Recipient's DH-KA public key, used by the JWS Producer during key agreement, as well as the KDF parameters necessary for deriving the MAC key.

This specification also defines new `alg` parameter values. These values are of the form `<HMAC alg param value>-PKDS-<n>`, where the prefix indicates the HMAC algorithm and `<n>` identifies the KDF. The ECDH curve is inferred from the JWS Recipient's DH-KA public key.

The method is useful in settings where pre-shared keys are undesirable or infeasible, and where direct key distribution or key wrapping introduces operational concerns. It enables the use of HMAC-based signatures that can be validated solely with information embedded in a JWS.

A primary motivation for this work is to enable HMAC signature validation from information contained within an {{SD-JWT}}, mirroring capabilities available in credential formats like {{mdoc MSO}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

The draft uses "JSON Web Signature", "JOSE Header", "JWS Signature", "JWS Signing Input" as defined by {{RFC7515}}.

Producer:
: The party that performs the DH-KA first, derives the MAC key via a KDF, constructs the JOSE Header and JWS Payload, and computes the JWS Signature.

Recipient:
: The party that performs the DH-KA second, derives the MAC key via information in the JWS, and validates the JWS using the MAC key according to {{RFC7515}}.

# Cryptographic Dependencies

DVS rely on the following primitives:

- A Diffie-Hellman Key Agreement (KA-DH), for example ECKA-DH defined in {{BSI-TR-03111}}:
    - `DH(skX, pkY)`: Perform a non-interactive Diffie-Hellman exchange using the private key `skX` and public key `pkY` to produce a Diffie-Hellman shared secret of length Ndh. This function can raise a ValidationError.
    - `Ndh`: The length in bytes of a Diffie-Hellman shared secret produced by `DH()`.
    - `Nsk`: The length in bytes of a Diffie-Hellman private key.

- A key derivation function (KDF), for example HKDF defined in {{RFC5869}}:
    - `Extract(salt, ikm)`: Extract a pseudorandom key of fixed length Nh bytes from input keying material `ikm` and an optional byte string `salt`.
    - `Expand(prk, info, L)`: Expand a pseudorandom key `prk` using optional string `info` into `L` bytes of output keying material.
    - `Nh`: The output size of the Extract() function in bytes.

- A Message Authentication Code algorithm (MAC), for example HMAC defined in {{RFC2104}}:
    - `MacSign(k, i)`: Returns an authenticated tag for the given input `i` and key `k`.
    - `Nk`: The length in bytes of key `k`.

# Designated Verifier Signatures

A designated verifier signature requires three components for an algorithm:

1. a Diffie-Hellman Key Agreement (DHKA)
2. a Key Derivation Function (KDF)
3. a Message Authentication Code algorithm (MAC)

In general, these parameters are chosen by the Signing Party. These parameters need to be communicated to the Verifying Party before the generation of a Designated Verifier Signature.


## Signature Generation

The generation of the Designated Verifier Signature takes the private key of the Signing Party, the public key of the Verifying Party and the message as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

Input:

 * `skS`: private key of the Signing Party
 * `pkR`: public key of the Verifying Party
 * `msg`: JWS Signing Input
 * `salt` : Salt for key derivation
 * `info` : optional info for key derivation

Function:

~~~
def dvsSign(skS, pkR, msg, salt= "", info = "DVS-1")

    dh =  DH(skS, pkR)
    prk = Extract(salt, dh)
    k = Expand(prk, info, Nk)
    signature = MacSign(k, msg)
    return signature
~~~

## Signature Verification

The generation of the Designated Verifier Signature takes the private key of the Signing Party, the public key of the Verifying Party and the message as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

Input:

 * `skR`: private key of the Verifying Party
 * `pkS`: public key of the Signing Party
 * `msg`: JWS Signing Input
 * `salt` : Salt for key derivation
 * `info` : optional info for key derivation
 * `signature` : the Message Authentication Code

Function:

~~~
def dvsVerify(skR, pkS, msg, salt = "", info = "DVS-1", signature)

    dh =  DH(skR, pkS)
    prk = Extract(salt, dh)
    k = Expand(prk, info, Nk)
    signature' = MacSign(k, msg)
    if signature != signature':
    raise Exception("Designated Verifier Signature invalid")
    return
~~~

## Signature Suites {#generic_suites}
Algorithms MUST follow the naming `DVS-<DHKA>-<KDF>-<MAC>`.

# Designated Verifier Signatures for JOSE

Designated Verifier Signatures behave like a digital signature as described in Section 3 of {{RFC7518}} and are intended for use in JSON Web Signatures (JWS) as described in {{RFC7515}}. The Generating Party performs the `Message Signature or MAC Computation` as defined by Section 5.1 of {{RFC7515}}. The Verifying Party performs the `Message Signature or MAC Validation` as defined by Section 5.2 of {{RFC7515}}.

The following JWS headers are used to convey Designated Verifier Signatures for JOSE:

 * `alg` : REQUIRED. The algorithm parameter describes the chosen signature suite, for example the ones described in (#generic_suites) and (#hpke_suites).
 * `rpk` : REQUIRED. The `rpk` (recipient public key) parameter represents the encoded public key of the Verifying Party that was used in the DHKA algorithm as a JSON Web Key according to {{RFC7517}}. This parameter MUST be present.
 * `nonce` : OPTIONAL. The `nonce` may be provided by the Verifying Party additional to it's public key and ensure additional freshness of the signature. If provided, the Signing Party SHOULD add the `nonce` to the header.

The Signing Party may use existing JWS header parameters like `x5c`, `jwk` or `kid` to represent or reference it's public key according to {{RFC7517}}.

## Example JWT

The JWT/JWS header:

~~~
{
    "typ" : "JWT",
    "alg" : "DVS-P256-SHA256-HS256",
    "jwk" : <JWK of the Signing Party>,
    "rpk" : <JWK of Verifying Party>
}
~~~

The JWT/JWS payload:

~~~
{
    "iss" : "https://example.as.com",
    "iat" : "1701870613",
    "given_name" : "Erika",
    "family_name" : "Mustermann"
}
~~~

The JWT/JWS signature:

~~~
base64-encoded MAC
~~~

This specification described instantiations of Designated Verifier Signatures using specific algorithm combinations:

~~~ ascii-art
+-----------------------+-----------------------------+----------------+
| Algorithm Name        | Algorithm Description       |                |
|                       |                             | Requirements   |
+-----------------------+-----------------------------+----------------+
| DVS-P256-SHA256-HS256 | ECDH using NIST P-256,      |   Optional     |
|                       | HKDF using SHA-256 and      |                |
|                       | HMAC using SHA-256          |                |
+-----------------------+-----------------------------+----------------+
| DVS-HPKE-Auth-X25519  | DVS based on HPKE using     |                |
| -SHA256               | DHKEM(X25519, HKDF-SHA256)  |  Optional      |
| -ChaCha20Poly1305     | HKDF-SHA256 KDF and         |  (Appendix A)  |
|                       | ChaCha20Poly1305 AEAD       |                |
+-----------------------+-----------------------------+----------------+
| DVS-HPKE-Auth-P256    | DVS based on HPKE using     |                |
| -SHA256-AES128GCM     | DHKEM(P-256, HKDF-SHA256)   |   Optional     |
|                       | HKDF-SHA256 KDF and         |   (Appendix A) |
|                       | AES-128-GCM AEAD            |                |
+-----------------------+-----------------------------+----------------+
~~~

# Security Considerations

## Replay Attack Detection
Verifying party MUST ensure the freshness of signatures by utilizing ephemeral keys in `rpk` or by providing a nonce for `nonce`.

## Limited Repudiability
A malicious verifiying party can weaken the repudiability property by involving certain third parties in the protocol steps.

- One method is to have a third party observe all protocol steps so that third party can be sure that the signature originates by the signer.
- Another method requires that the verifying party's public key is a shared key that has previously been calculated with the keys of certain specific third parties so that the proof of authenticity can be done with Multi Party Computation involving all parties (see {{TLS-NOTARY}}).


# IANA Considerations

Define:

- define new `rpk` header parameter
- alg values for DVS-P256-SHA256-HS256 and some more

--- back

# Designated Verifier Signatures using HPKE

This section describes a simple designated verifier signature scheme based on Hybrid Public Key Encryption (HPKE) {{RFC9180}} in auth mode.
It reuses the authentication scheme underlying the AEAD algorithm in use, while using the KEM to establish a one-time authentication key from a pair of KEM public keys.
This scheme was described in early specification drafts of HPKE {{RFC9180}}

## Cryptographic Dependencies

- An HPKE algorithm (for the HPKE variants):
- `SealAuth(pkR, info, aad, pt, skS)`: encrypts and authenticates single plaintext `pt` with associated data `aad` and context `info` using a private sender key `skS` and public receiver key `pkR`.
- `OpenAuth(enc, skR, info, aad, ct, pkS)`: decrypts ciphertext and tag `ct` with associated data `aad` and context `info` using a private receiver key `skR` and public sender key `pkS`.

## Signature Generation

To create a signature, the sender simply calls the single-shot `Seal()` method with an empty plaintext value and the message to be signed as AAD.
This produces an encoded key enc and a ciphertext value that contains only the AAD tag. The signature value is the concatenation of the encoded key and the AAD tag.

Input:

* `skS`: private key of the Signing Party
* `pkR`: public key of the Verifying Party
* `msg`: JWS Signing Input
* `info` : optional info for key derivation

Steps:

1. Call `enc`, `ct` = `SealAuth(pkR, info, aad, pt, skS)` with
* `aad` = `msg`
* `pt` = ""
2. JWS Signature is the octet string concatenation of (`enc` \|\| `ct`)

## Signature Verification

To verify a signature, the recipient extracts encoded key and the AAD tag from the signature value and calls the single-shor `Open()` with the provided ciphertext.
If the AEAD authentication passes, then the signature is valid.

Input:

* `skR`: private key of the Verifying Party
* `pkS`: public key of the Signing Party
* `msg`: JWS Signing Input
* `info` : optional info for key derivation
* `signature`: JWS Signature octet string

Steps:

1. Decode `enc` \|\| `ct` = `signature` by length of `enc` and `ct`. See {{HPKE-IANA}} for length of ct and enc.
2. Call `pt` = `OpenAuth(enc, skR, info, aad, ct, pkS)` with
* `aad` = msg
3. the signature is valid, when `OpenAuth()` returns `pt` = "" with no authentication exception

NOTE: `ct` contains only a tag. It's length depends on the AEAD algorithm (see Nt values in RFC9180 chapter 7.3.)

## Signature Suites {#hpke_suites}
Algorithms MUST follow the naming `DVS-HPKE-<Mode>-<KEM>-<KDF>-<AEAD>`.
"Mode" is Auth (PSKAuth could also be used).
The "KEM", "KDF", and "AEAD" values are chosen from the HPKE IANA registry {{HPKE-IANA}}.


# Acknowledgments

Thanks to:

- Brian Campbell
- John Bradley


