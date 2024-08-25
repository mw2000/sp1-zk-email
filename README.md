# SP1-ZK-Email
This is my attempt at re-writing the original email-verifier circuit written by the zk-email team in [this repository](https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/email-verifier.circom) into an sp1 circuit. The reason for doing so is two-fold:
- Make the code more readable and maintable in a higher-level language.
- Just learn more about zk-email and how it works by writing code.

The only drawback is the performance drawbacks in the short term, but with advancements within zk, sp1's internal tuning, as well as the existing sp1 prover network, we expect this drawback to be non-important in the medium to long term.