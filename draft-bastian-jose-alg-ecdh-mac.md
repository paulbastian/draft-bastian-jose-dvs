---
title: "JOSE algorithms for ECDH-MAC-based signatures"
abbrev: "ECDH-MAC for JOSE"
category: info

docname: draft-bastian-jose-alg-ecdh-mac-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Javascript Object Signing and Encryption"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: "Javascript Object Signing and Encryption"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  github: "paulbastian/paulbastian-jose-ecdh-mac-algorithms"
  latest: "https://paulbastian.github.io/paulbastian-jose-ecdh-mac-algorithms/draft-bastian-jose-alg-ecdh-mac.html"

author:
 -
    fullname: Paul Bastian
    organization: Bundesdruckerei GmbH
    email: paul.bastian@bdr.de

normative:
  RFC7517: RFC7517
  RFC7518: RFC7518

informative:


--- abstract

This specification defines a JSON Web Algorithm for JOSE, that uses a combination of key agreement and MAC to construct a signature-like mechanism.

--- middle

# Introduction

JWS defines cryptographic algorithms to digitally sign or create Message Authentication Codes (MAC) of the contents of the JWS Protected Header and the JWS Payload in Section-3 {{RFC7518}}. JWS also offers ephemeral-static Elliptic Curve Diffie-Hellman key exchange in combination with a key derivation function ("ECDH-ES" and its variations) as a mechanism for key management in Section-4.6 {{RFC7518}}, however these are only used for symmetric encryption.

This specification describes a combination of an ECDH key exchange with a MAC, that enables a feature set that is similar to digital signatures with repudiation.

This specification and all described algorithms should respect the efforts for Fully Specified Algorithms (https://www.ietf.org/archive/id/draft-jones-jose-fully-specified-algorithms-00.html).

This algorithm is intended for use with digital credentials ecosystems, including the Issuer-Holder-Verifier model described by W3C VCDM or IETF SD-JWT-VC.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

Generating Party:
: The Party that performs the key agreement first and generates the MAC. Similar to a Signer.

Verifying Party:
: The Party that performs the key agreement second, generates the MAC and compares it to a given value. Similar to a Verifier.

# Parameters

For the generation of an ECDH-based MAC the following parameters must be chosen:

1. the domain parameters for the ECDH "curve"
2. the key derivation algorithm "kd"
3. the MAC algorithm "mac"

In general, these parameters are chosen by the Generating Party. These parameters need to be communicated to the Verifying Party before the generation of an ECDH-based MAC.

# Cryptographic Algorithm

The generation of the ECDH-based MAC takes the private key of the Generating Party and the public key of the Verifying Party as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

The generation of ECDH-based MAC follows these steps:

1. Perform ECDH as defined as defined by "curve"
  - use the specified elliptic curve to generate a key pair and set the `epk`
  - use the Verifier's public key defined by `kid` to perform the key agreement
  - optionally provide a certificate chain defined by `x5c`
2. Derive symmetric key as defined by "kd"
  - use the output from the key agreement as an input for the key derivation algorithm
  - derive the MAC key
3. Generate a MAC as defined by "mac"
  - use the output from the key derivation algorithm as an input for the MAC algorithm
  - generate the MAC

The verification of ECDH-based MAC follows these steps:

1. Perform ECDH as defined as defined by "curve"
  - use the specified elliptic curve to generate an ephemeral key pair and set the `kid`
  - provide the public key `kid` to the Generating Party
  - use the Generating Party's public key defined by `epk` and perform the key agreement
  - optionally validate the certificate chain defined by `x5c`
2. Derive symmetric key as defined by "kd"
  - use the output from the key agreement as an input for the key derivation algorithm
  - derive the MAC key
3. Generate a MAC as defined by "mac"
  - use the output from the key derivation algorithm as an input for the MAC algorithm
  - generate the MAC
  - compare the generated MAC with the signature value

## Header parameter "alg"

The following values MUST be used for the "alg" header parameter:
```
+------------------+--------------------------------+-----------------+
| Algorithm Name   | Algorithm Explanation          | Implementation  |
|                  |                                | Requirements    |
+------------------+--------------------------------+-----------------+
| ECDH-P256-HS256  | ECDH using NIST P-256 and      | Optional        |
|                  | HMAC using SHA-256             |                 |
| ECDH-BP256-HS256 | ECDH using BrainpoolP256r1 and | Optional        |
|                  | HMAC using SHA-256             |                 |
+------------------+--------------------------------+-----------------+
```
Other algorithms SHOULD follow the naming `ECDH-<elliptic curve domain parameters>-<KD algorithm>-<MAC algorithm>`.

## Header parameter "epk"
The "epk" (ephemeral public key) value is created by the Generating Party for the use in the key agreement algorithm. This header parameter MUST be present and MUST contain the Generating Party's public key represented as a JSON Web Key according to {{RFC7517}}. It MUST contain only public key parameters and SHOULD contain only the minimum JWK parameters necessary to represent the key. Other JWK parameters included may be checked for consistency or may be ignored.

## Header parameter "x5c"
The "x5c" (X.509 certificate chain) value is created by the Generating Party for the trust management of the "epk". This header parameter is OPTIONAL and if present MUST contain the X.509 certificate chain with the JWK from "epk" being the public key of the leaf certificate. Alternatively, the Generating Party may use "x5t", x5t#S256" or "x5u".

## Header parameter "kid"
The "kid" (key identifier) value is created by the Generating Party for the use in the key agreement algorithm. This header parameter MUST be present and MUST contain the Verifying Party's public key ID user by the Generating Party for the ECDH.

## Example JWT

The JWT/JWS header:
```
{
    "typ" : "JWT",
    "alg" : "ECDH-P256-HS256",
    "x5c" : <issuer certificate chain that signs the epk>,
    "epk" : <JWK used for ECDH>,
    "kid" : <key ID of Verifying Party>
}
```

The JWT/JWS payload:
```
{
    "iss" : "https://example.as.com",
    "iat" : "1701870613",
    "given_name" : "Erika",
    "family_name" : "Mustermann"
}
```

The JWT/JWS signature:
```
base64-encoded MAC
```

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
