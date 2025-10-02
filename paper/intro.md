## Q&A for intro

- *What specific problem are we addressing?*                 
    - Existing digital identity wallets, such as those using SD-JWT or ISO 18013-5 (mDL), currently do not provide unlinkable proofs of credentials. Furthermore, existing approaches (like BBS# or Google's anonymous credentials) either rely on pairing-based cryptography, introduce trusted setups, or fail to offer a clear migration path to post-quantum cryptography. There is a need for a modular, efficient, and easily integrable ZK solution compatible with existing credential formats.
- *What is the exact scope of this paper?*                   
    - We propose and describe a modular zk-SNARK wrapper that takes a standard credential format (such as SD-JWT or any W3C-compliant Verifiable Credential) and outputs a succinct, unlinkable proof. We do not build a complete wallet solution, nor do we handle credential revocation or user-interface considerations.
- *What adversary model do we consider?*
    - We assume a malicious credential holder who may attempt to forge or reuse proofs, colluding verifiers who aim to link proofs and track users, and an honest-but-curious issuer. Resistance against quantum adversaries and side-channel attacks on secure elements are left for future work.                     
- *What cryptographic assumptions underpin our solution?*    
    - Our security relies solely on discrete-logarithm hardness in the Tom256 group, together with the knowledge-soundness and zero-knowledge properties of Spartan interactive-oracle proofs under the random-oracle model. No trusted setup or pairing assumptions are required.
- *How can our approach be summarised simply?*               
    - "Pre-process once, reuse many times." We separate the proof-generation into two phases: an offline 'prepare' step proving issuer signature verification, parsing, and hashing, followed by a lightweight online 'show' step for selective disclosure and device-binding at each presentation.
- *What are our main technical contributions?*               
    1. A clear **prepare/show** circuit decomposition tailored specifically for standard credential formats. 
    2. A simplified proof-linking method using **Hyrax vector commitments**, eliminating extra linking gadgets such as MACs.
    3. Consistent arithmetic over a single field (Tom256), removing the complexity of cross-field arithmetic.
- *What security and functional properties do we achieve?*   
    - Our construction guarantees statistical zero-knowledge, knowledge soundness, **unlinkability across presentations**, selective disclosure of arbitrary predicates, **proof re-randomisation**
- *What are the key design principles of zkID?*
- *What is the high-level flow of the solution?*             
    - An Issuer provides the credential to the Wallet along with an ECDSA signature. The Wallet executes a one-time offline `prepare` step, generating and caching Hyrax vector commitments. At presentation time, the Wallet signs the verifier's challenge nonce using its secure device key, computes a lightweight `show` proof reusing cached commitments, and sends these to the Verifier. The Verifier then checks the Spartan proof and the equality of commitments.
- *Is there a clear migration path to post-quantum security?*
    - N/A
- *What implementation progress have we made?*         
    - We have built a research-grade implementation consisting of a Spartan backend operating over the Tom256 curve, a Hyrax commitment library, an offline batch-generation CLI, and an Android-compatible JNI stub for the online prover. Integration into a complete wallet remains future work.      
- *How do we compare to existing solutions?*  
    - Pairing-based BBS# lacks predicate proofs and requires non-standard curves;
    - Google?;
    - Microsoft’s Crescent relies on a trusted KZG setup.
    - zkID provides selective disclosure and linking without trusted setup, relies on standardised cryptographic assumptions,...
- *What limitations do we currently acknowledge?*         
    - Actual end-to-end performance metrics and memory profiles can only be accurately measured after integration with a full wallet implementation. **We leave credential revocation mechanisms**, side-channel resilience of hardware devices, and post-quantum instantiation as explicit future research
- *What real-world use cases or deployment scenarios would benefit most from zkID’s unlinkable proof capabilities in digital identity systems?*


