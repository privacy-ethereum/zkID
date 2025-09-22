# Revocation

This work explores the design and evaluation of revocation strategies for verifiable credentials, with a focus on analyzing the trade-offs between different cryptographic approaches.

Revocation is critical for maintaining trust, without it, verifiers cannot know whether a credential is still valid, which undermines the entire system. At the same time, existing revocation mechanisms often compromise user privacy.

The goal of this work is to provide a framework that allows verifiers to reliably detect whether a credential has been revoked, while minimizing disclosure of personal data.

## Resources

- Merkle Tree-based Revocation Methods: https://hackmd.io/@vplasencia/ryRJo9uilx

- DIF Revocation Report: https://github.com/decentralized-identity/labs-privacy-preserving-revocation-mechanisms/blob/main/docs/report.md
