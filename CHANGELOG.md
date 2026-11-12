# Changelog

## [0.9.0-SNAPSHOT]
### Features
* DID recipients. `DidRecipientId` parses and builds `ruhnu/did/<did:web DID>/hash/<fingerprint>`
  identifiers, where the fingerprint is the unpadded base64url SHA-256 of the OpenSSH public key blob.
  `DidWeb` parses did:web DIDs (domain names only, optional `%3A` port, `:` path segments, no `.` or `..` segments or percent-encoded URL delimiters) and maps
  them to their `did.json` URL.
* `DidWebResolver` fetches a DID document with one HTTPS GET: no redirects, an overall deadline that
  covers the body, a body size limit and a `DidHostPolicy` checked before any request. It classifies
  the result as `Found`, `NotFound` or `Unavailable`. `DidDocumentKeys` extracts the EC P-256
  `publicKeyJwk` keys a document lists under `authentication` with the DID as `controller`.
* `DidAuthTokenVerifier` verifies ES256 auth tokens of DID recipients: the signing key travels in the
  JWS `jwk` header and its fingerprint must equal the one in `iss`. The caller checks the share
  recipient and that the DID document still lists the key.
* `AuthTokenCreator.Builder.withHeaderJwk(JWK)` puts the signing key's public JWK into the JWS header.
* `SshPublicKeyParser.blobFromPublicKey`, `openSshFingerprint` and `fingerprintBase64Url`.

## [0.8.0-SNAPSHOT]
### Features
* SSH public key recipients. `SshPkAuthTokenVerifier` verifies ES256 auth tokens whose `iss` is a
  `ruhnu/pk/<base64 OpenSSH public key blob>` identifier, using the ECDSA P-256 public key decoded
  from `iss`. No certificate or trust store is needed; the caller compares the returned identifier
  with the share recipient.
* `SshPublicKeyParser` parses `ruhnu/pk/` identifiers and OpenSSH public key lines
  (`ecdsa-sha2-nistp256` only), builds identifiers from them, validates their canonical form and
  computes OpenSSH `SHA256:` fingerprints.
* `AuthTokenCreator.Builder.withIssuer(String)` creates auth tokens for non-ETSI issuers.

## [0.7.3]
### Bug Fixes
* Fix RP counter-signature not being bound to the auth token it accompanies. `AuthTokenVerifier`
  now verifies that the RP counter-signature's `x-rp-signed-hash` matches
  `SHA-256(signedJWT.getSignature())` of the token being verified, for both MID- and SID
  RPv3-signed tokens, so a countersignature captured from a different, unrelated session can no
  longer be paired with another valid auth token to pass verification.

## [0.7.2]
### Improvements
* Improve the exception handling
* Code cleanup

## [0.7.1]
### Improvements
* Dependency updates

## [0.7.0]
### Improvements
* RSA support for MID Auth tokens

## [0.6.0]
### Features
* Session token verification for the Mobile-ID usecase
* HTTP signature verification for auth tokens

## [0.5.0]
### Features
* Session token verification for the Smart-ID usecase
* Smart-ID RPv3 signature verification for auth tokens

## [0.3.3] First public release

## [0.3.3-SNAPSHOT] Improvements to 0.3.2-SNAPSHOT

### Changes
* Add slf4j-api and change logback-classic scope to test.

## [0.3.2-SNAPSHOT] Bugfixes 0.3.1-SNAPSHOT

### Bug Fixes
* Fix "java.lang.ClassNotFoundException: org.bouncycastle.cert.jcajce.JcaX509CertificateHolder" 
  when validating "ES256" JWT tokens. Nimbus library depends (optional) on 
  `org.bouncycastle:bcpkix-jdk18on:1.80` when parsing certificates with EC keys.

## [0.3.1-SNAPSHOT] Improvements to 0.3.0-SNAPSHOT

### Changes
* add `EtsiIdentifier.PREFIX` const
* make `AuthTokenCreator.sign(JWSSigner, JWSAlgorithm)` public to support JWSSigner with multiple algorithms.

### Bug Fixes
* Fix EtsiIdentifierTests
* When verifying auth-token with EC certificate, determine EC curve from certificate instead of using hard-coded `P256`
* Previously first RSA JWSAlgorithm was selected from JWSSigner supported algorithms (that happened to be `RS256`).
  RSA JWT algorithm must now be explicitly specified or JWSSigner must support single algorithm (like SIDAuthJWSSigner does)


## [0.3.0-SNAPSHOT] Support for signing with EC keys

### Features

* Support for signing and verifying auth-token with EC keys (ES256) to support Mobile-ID

## [0.2.0-SNAPSHOT] First public pre-release 

### Bug Fixes
* Fix Disclosure decoding (previously Disclosure were incorrectly decoded even when digest didn't match )

### Changes
* Use "aud" list of `{server_base_url}/key-shares/{shareID}?nonce={nonce}` URLs instead of custom "shareAccessData" json object.
* remove "kid" from JWT header (duplicate of "iss" in JWT body)
* remove "iat" and "exp" claims. Instead `nonce` creation time is checked by `cdoc2-shares-server`
* Move x5c certificate issuer check into `cdoc2-auth-token` module (from `cdoc2-shares-server`)