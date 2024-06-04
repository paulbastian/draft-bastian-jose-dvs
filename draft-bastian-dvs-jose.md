---
title: "Designated Verifier Signatures for JOSE"
abbrev: "DVS for JOSE"
category: info

docname: draft-bastian-dvs-jose-latest
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
  github: "paulbastian/draft-bastian-dvs-jose"
  latest: "https://paulbastian.github.io/draft-bastian-dvs-jose/draft-bastian-dvs-jose.html"

author:
 -
    fullname: Paul Bastian
    organization: Bundesdruckerei GmbH
    email: bastianpaul@googlemail.com

normative:
  RFC7515: RFC7515
  RFC7517: RFC7517
  RFC7518: RFC7518

informative:


--- abstract

This specification defines designated verifier signatures for JOSE and defines algorithms that use a combination of key agreement and MACs.

--- middle

# Introduction

Designated verifier signatures (DVS) are signature schemes in which signatures are generated, that can only be verified a particular party. Unlike conventional digital signature schemes like ECDSA, this enables repudiable signatures.

This specification describes a general structure for designated verifier signature schemes and specified a set of instantiations that use a combination of an ECDH key exchange with an HMAC.

This specification and all described algorithms should respect the efforts for Fully Specified Algorithms (https://www.ietf.org/archive/id/draft-jones-jose-fully-specified-algorithms-00.html).

This algorithm is intended for use with digital credentials ecosystems, including the Issuer-Holder-Verifier model described by W3C VCDM or IETF SD-JWT-VC.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Terminology

The draft uses "JSON Web Signature", "JOSE Header", "JWS Signature", "JWS Signing Input" as defined by {{7515}}.

Signing Party:
: The Party that performs the key agreement first and generates the MAC. Similar to a Signer.

Verifying Party:
: The Party that performs the key agreement second, generates the MAC and compares it to a given value. Similar to a Verifier.

# Cryptographic Dependencies

DVS uses the following notation:

DVS rely on the following primitives:

# Designates Verifier Signatures

A designated verifier signature requires three components for an algorithm:

1. a Diffie-Hellman Key Agreement (DHKA)
2. a Key Derivation Function (KDF)
3. a Message Authentication Code algorithm (MAC)

In general, these parameters are chosen by the Signing Party. These parameters need to be communicated to the Verifying Party before the generation of a Designated Verifier Signature.

## Signature Generation

The generation of the Designated Verifier Signature takes the private key of the Signing Party, the public key of the Verifying Party and the message as inputs. The retrieval and communication of the Verifying Party's public key is out of scope of this specification and subject to the implementing protocols.

The generation of the signature follows these steps:

1. Perform the key agreement as defined by the DHKA algorithm
  - use the specified elliptic curve to generate a key pair and set the `epk`
  - use the Verifier's public key defined by `kid` to perform the key agreement
  - optionally provide a certificate chain defined by `x5c`
2. Extract and expand the shared secret as defined by KDF algorithm
  - use the output from the key agreement as an input for the key derivation algorithm
  - derive the MAC key
3. Generate a MAC as defined by MAC algorithm
  - use the output from the key derivation algorithm as an input for the MAC algorithm
  - use the `JWS Signing Input` as defined in Section 5.1 if {{7515}} as the `message` input for the MAC algorithm
  - generate the MAC

The verification of signature follows these steps:

1. Perform key agreement as defined by the DHKA algorithm
  - use the specified elliptic curve to generate an ephemeral key pair and set the `kid`
  - provide the public key `kid` to the Signing Party
  - use the Signing Party's public key defined by `epk` and perform the key agreement
  - optionally validate the certificate chain defined by `x5c`
2. Extract and expand the shared secret as defined by KDF algorithm
  - use the output from the key agreement as an input for the key derivation algorithm
  - derive the MAC key
3. Generate a MAC as defined by MAC algorithm
  - use the output from the key derivation algorithm as an input for the MAC algorithm
  - generate the MAC
4. Compare the generated MAC with the signature value

# Designated Verifier Signatures for JOSE

Designated Verifier Signatures behave like a digital signature as described in Section 3 of {{7518}} and are intended for use in JSON Web Signatures (JWS) as described in {{7515}}. The Generating Party performs the `Message Signature or MAC Computation` as defined by Section 5.1 of {{7515}}. The Verifying Party performs the `Message Signature or MAC Validation` as defined by Section 5.2 of {{7515}}.

The following JWS headers are used to convey Designated Verifier Signatures for JOSE:

 * `alg` : The algorithm parameter describes the chosen signature suite, for example the ones described in (#suites)
 * `jwk` : The `jwk` parameter represents the encoded public key of the Signing Party for the use in the DHKA algorithm as a JSON Web Key according to {{RFC7517}}. It MUST contain only public key parameters and SHOULD contain only the minimum JWK parameters necessary to represent the key. Usage of this parameter MUST be supported.
 * `x5c` : The `x5c` parameter represents the encoded certificate chain and its leaf public key of the Signing Party for the use in the DHKA algorithm as a X.509 certificate chain according to {{RFC7517}}. Alternatively, the Signing Party may use "x5t", x5t#S256" or "x5u". Usage of this parameter MAY be supported.
 * `rpk` : The `rpk` (recipient public key) parameter represents the encoded public key of the Verifying Party that was used in the DHKA algorithm as a JSON Web Key according to {{RFC7517}}. This parameter MUST be present.

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

# Signature Suites {#suites}

Algorithms MUST follow the naming `DVS-<DHKA>-<KDF>-<MAC>`.

This specification described instantiations of Designated Verifier Signatures using specific algorithm combinations:

~~~ ascii-art
+-----------------------+-----------------------------+----------------+
| Algorithm Name        | Algorithm Description       |                |
|                       |                             | Requirements   |
+-----------------------+-----------------------------+----------------+
| DVS-P256-SHA256-HS256 | ECDH using NIST P-256,      | Optional       |
|                       | HKDF using SHA-256 and      |                |
|                       | HMAC using SHA-256          |                |
+--------------------+--------------------------------+----------------+
~~~

# Security Considerations

TODO Security


# IANA Considerations

Define:

- `rpk` header parameter
- alg values for DVS-P256-SHA256-HS256 and some more


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
