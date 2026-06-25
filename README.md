# Disclosure Ledger Verifier

A reference implementation for independently verifying the integrity of a
**disclosure ledger** — a structured, cryptographically sealed record of verified
facts about an organisation, published in machine-readable form.
<org>
This verifier lets anyone confirm that a published ledger has not been altered
since publication, **without needing to trust the publisher**. It runs fully
offline against the published files.

## What it verifies

A disclosure ledger has two integrity layers, and this tool checks both:

1. **Row seals.** Every record carries an `apparat_seal`: a SHA-256 hash computed
   over the canonical four-field set `{context, label, source_url, value}`. The
   verifier recomputes each seal from the record's own contents and confirms it
   matches the published seal. Any alteration to a sealed field — a changed value,
   an edited quote, a swapped source — produces a different hash and is detected.

2. **Release commitment.** All row seals are combined into a single Merkle root,
   published as `release_commitment` in `release.json`. The verifier recomputes
   the root from the row seals and confirms it matches. This binds the entire
   ledger into one commitment.

A third layer — **anchoring** in a public transparency log (Sigstore Rekor) —
provides third-party-verifiable evidence that the release existed at a specific
time. Verifying the Rekor entry is an optional online step described below; the
core integrity proof in this tool requires only the local files.

## Installation

The verifier is a single Python file with no third-party dependencies (standard
library only). Python 3.8 or later.

```bash
git clone https://github.com/disclosure-ledger/disclosure-ledger-verifier.git
```

## Usage

Verify a local ledger's row seals:

```bash
python3 verify_disclosure_ledger.py --ledger ledger.json
```

Verify seals **and** the release commitment:

```bash
python3 verify_disclosure_ledger.py --ledger ledger.json --release release.json
```

Verify a ledger published at a URL:

```bash
python3 verify_disclosure_ledger.py --url https://disclosures.example.org/ledger.json
```

### Example

The `examples/` directory contains a small real-data ledger and its release file:

```bash
python3 verify_disclosure_ledger.py \
    --ledger examples/sample-ledger.json \
    --release examples/sample-release.json
```

Expected output:

```
VERIFIED — 4/4 rows intact, release commitment matches.
```

### Exit codes

| Code | Meaning |
| :--- | :------ |
| 0    | All checks passed |
| 1    | One or more checks failed (tampering detected) |
| 2    | Usage or input error |

These make the verifier usable in automated checks (CI, monitoring).

## How the seal is computed

The seal is the SHA-256 of a canonical JSON serialisation of exactly four fields,
in this order:

```
{"context":"…","label":"…","source_url":"…","value":"…"}
```

Canonicalisation rules:

- **Keys in fixed order**: `context`, `label`, `source_url`, `value` — insertion
  order, *not* alphabetical.
- **No whitespace** between tokens (compact separators `,` and `:`).
- **Non-ASCII characters preserved** (not `\u`-escaped); the string is encoded as
  UTF-8 before hashing.

This is byte-for-byte equivalent to JavaScript's `JSON.stringify` over the same
object, which is how the reference generator produces seals. Any conforming
implementation that reproduces these rules will compute identical seals.

## How the Merkle root is computed

```
1. Collect all row seals (hex strings).
2. Sort them lexicographically.
3. Repeatedly combine adjacent pairs: concatenate the two hex strings and take
   SHA-256 of the UTF-8 bytes of the concatenation. An odd element at the end of
   a layer is paired with itself.
4. Continue until one root remains — the release commitment.
```

## Optional: verifying the Sigstore Rekor anchor

When a `release.json` includes an `anchor` block with `anchor_status: "anchored"`,
the release commitment has been signed and submitted to
[Sigstore Rekor](https://docs.sigstore.dev/logs/overview/), a public transparency
log operated by the Linux Foundation. This provides independent, timestamped
evidence that the release existed in its published form.

To verify the anchor online, you can:

1. Fetch the Rekor entry at the `rekor_entry_url` in `release.json`.
2. Confirm the entry's `hash` matches the `release_commitment`.
3. Confirm the signature verifies against the publisher's public key
   (`public_key_url`), and that the key fingerprint matches.

A scripted Rekor check is planned as an optional extension. The offline checks in
this verifier already prove that the ledger contents are internally consistent and
match their published commitment; the Rekor step adds independent proof of *when*
that commitment was published.

## Specification

This verifier implements the integrity checks of the disclosure-ledger format.
The full specification — data model, field semantics, canonicalisation, and
conformance requirements — is published separately. (Link to be added.)

## License

This reference verifier is released under the MIT License. See `LICENSE`.
