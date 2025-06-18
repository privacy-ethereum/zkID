# annex notes

## links:

- annex 2: https://eu-digital-identity-wallet.github.io/eudi-doc-architecture-and-reference-framework/1.4.0/annexes/annex-2/annex-2-high-level-requirements/
- technical specifications: https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts1-eudi-wallet-trust-mark.md

## vocab:

- relying party = verifier
- wallet holder / user = prover
- EAA "EUDI attribute authority" = issuer
- OpenID4VP - remote flow where user probes verifier, which then has to probe a remote wallet
- QEAA - document containing attestations (e.g. diplomas, student IDs, etc), slightly diff from PID in scope but same technically
- proximity flow - ID verification over e.g. NFC tap rather than over a remote network connection

## topics relevant to our paper's scope (wrapper around credential for presentation flow):

- topic 1 -- device binding and stuff, also remote flows...
- topic 3 -- need to support [ISO18013-5] (format for mDLs) as well as SD-JWT
- topic 6 -- relying party authentication: verifier proves identity to prover
- topic 11 -- pseudonym rule book --- but it doesn't exist yet.
  - pseudonyms -- can do a nullifier hash = hash(pk, random_secret_salt)
- topic 18 -- presenting multiple credentials at once: need to provide proof-of-association, in case the credentials were issued to a diff public key controlled by the WCSD (this would need to be verified privately inside the SNARK to hide the public keys)

## main spec notes from above:

- has to support attestation in mDL standard [ISO18013-5] (CBOR format) and SD-JWT formats
- has to support presentations as defined mDL standard [ISO18013-5] and OpenID4VP standard for verifiable credentials
- PID Provider Trusted List -- so can theoretically make issuer private (with merkle inclusion proof or something)

## side topics (still high-priority security concerns that support need for ZKPs):

- topic 7: security issues but also not our scope if there is some sort of revocation registry, then likely need public list of keys that are still valid -> even if signature verification for device-binding is private, adversary can still do signature against this public list to de-anonymize, if the credential is not used by many people. still better than having to phone home to get revocation info
- topic 12: attestion rulebooks for other types of attestations, also mentions that some may be defined by [W3C verifiable credentials standard](https://www.w3.org/TR/vc-data-model-2.0/#presentations)
- topic 17: in instances where user wants to provide PID to authenticate/link to some account, need to also present credential directly tied to account access at the same time --> extra potential for linkability --> further need for re-randomizable presentation per credential
- topic 19 -- EUDI Wallet User navigation requirements (Dashboard logs for transparency): need to have a dashboard of transaction logs that cannot be altered/deleted (either local or external) (DASH_06)
- topics 25-26 - attestation rulebook online saying what attestations can be issued/requested/ by issuers/provers/. can aso include non-qualified EAAs. no regulation around it. (this mostly defines issuer behavior/is referenced pre-issurance, so it should not lead to phoning home)
- topic 27: issurance of certificates for verifiers -- also need to ensure no phone home (if verifier is like, a store or sth) for civilian verifiers
- topic 28: legal and natural PIDs are different. i wonder if this would lead to potential discrimination, i.e. if verifier requests more attributes that would reveal this information. e.g. DOB is not necessary for legal, but is for natural.
