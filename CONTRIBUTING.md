# Contributing to SCPE

SCPE has reached the stage where its quality is protected by what it **refuses** to add.
In a protocol, simplicity is not aesthetics — it is a technical property. It is what makes
independent implementations converge and what actually raises the odds of adoption. So the
bar for any change is deliberately high.

## The one rule

Every change answers one question:

> **Does this reduce or increase what an implementer must carry in their head?**

If it increases that load, it needs an extraordinarily strong reason to enter.

Every pull request states, in its description:

```
Complexity added:   <what a new implementer now has to understand>
Complexity removed: <what they no longer do>
```

A change that only adds is the exception, not the norm.

## The v1.0 gate

**No new capability enters v1.0 unless it eliminates a real limitation reported by an external
user or implementer.** Not an imagined one. This forces SCPE's evolution to be driven by
evidence, not imagination — the difference between a protocol that stays elegant for a decade
and one that bloats before it finds its first users.

## The 15-minute test

The docs are done when someone can open the repo and, in fifteen minutes, answer:

1. What is it?
2. What does it solve?
3. How does it work?
4. How do I implement it?
5. How do I verify?
6. What does it **not** solve?

If it takes an hour, there is too much documentation, not too little.

## Three implementations, one result

The strongest evidence that SCPE is a real protocol is not documentation — it is that three
independent verifiers, written in three languages by three different mental models
(`reference/standalone/verify_envelope.py`, `impl/go/`, and `impl/rust/`), reach the **same
verdict** — the same status and attestation summary — on every one of the normative vectors in
`spec/test-vectors/`. (The conformance contract is the verdict each vector's `expected.json`
records, not the free-text detail line, which may differ in wording between implementations.)
Any change to the spec or a verifier must keep all three implementations passing all vectors.
The conformance vectors are the contract; adding a vector for a newly-clarified behavior is
always welcome.

## What is out of scope

No whitepaper, no manifesto, no vision document, no reputation or scoring system, no central
server, no bespoke PKI. See `docs/design-decisions.md` and `docs/comparison.md` for why.
