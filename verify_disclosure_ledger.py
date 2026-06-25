#!/usr/bin/env python3
"""
Disclosure Ledger Verifier — reference implementation.

Independently verifies the integrity of a disclosure ledger published in the
Apparat format, with no need to trust the publisher. Runs fully offline against
published files.

Two layers of verification:

  1. Row seals    — for each record, recompute the SHA-256 seal over the
                    canonical {context, label, source_url, value} and confirm it
                    matches the published `apparat_seal`.
  2. Release root — recompute the Merkle root over the sorted row seals and
                    confirm it matches the `release_commitment` in release.json.

Anchoring (Sigstore Rekor) verification is an optional online extension,
documented in the README; this reference verifier proves integrity from local
files alone.

Usage:
    python3 verify_disclosure_ledger.py --ledger ledger.json
    python3 verify_disclosure_ledger.py --ledger ledger.json --release release.json
    python3 verify_disclosure_ledger.py --url https://disclosures.example.org/ledger.json

Exit codes:
    0  all checks passed
    1  one or more checks failed
    2  usage / input error
"""

import argparse
import hashlib
import json
import sys
import urllib.request


# ─────────────────────────────────────────────────────────────────────────────
# Core: canonical seal computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_seal(context, label, source_url, value):
    """
    Recompute a row's SHA-256 seal.

    The canonical form is a JSON object with EXACTLY these four keys, in THIS
    order (context, label, source_url, value), serialized with no whitespace and
    without escaping non-ASCII characters — byte-for-byte equivalent to
    JavaScript's JSON.stringify over the same object. The SHA-256 of that UTF-8
    byte string is the seal.

    Key order is significant: it is insertion order, not alphabetical.
    """
    canonical = json.dumps(
        {
            "context":    str(context if context is not None else ""),
            "label":      str(label if label is not None else ""),
            "source_url": str(source_url if source_url is not None else ""),
            "value":      str(value if value is not None else ""),
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# Core: Merkle root computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_merkle_root(hex_hashes):
    """
    Recompute the Merkle root over a list of hex seal strings.

    Procedure (matching the Apparat reference generator):
      - sort the seal strings lexicographically
      - repeatedly combine adjacent pairs by concatenating their hex strings and
        taking SHA-256 of the UTF-8 bytes of that concatenation
      - an odd element at the end of a layer is paired with itself
      - continue until a single root remains

    Returns None for an empty list; returns the single element unchanged for a
    one-element list.
    """
    if not hex_hashes:
        return None
    layer = sorted(hex_hashes)
    if len(layer) == 1:
        return layer[0]
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            a = layer[i]
            b = layer[i + 1] if i + 1 < len(layer) else layer[i]
            combined = (a + b).encode("utf-8")
            nxt.append(hashlib.sha256(combined).hexdigest())
        layer = nxt
    return layer[0]


# ─────────────────────────────────────────────────────────────────────────────
# Loading
# ─────────────────────────────────────────────────────────────────────────────

def load_json(path_or_none, url_or_none):
    if url_or_none:
        with urllib.request.urlopen(url_or_none, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    with open(path_or_none, "r", encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# Verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_rows(ledger):
    """Verify every row seal. Returns (ok_count, failures, recomputed_seals)."""
    failures = []
    recomputed = []
    for idx, row in enumerate(ledger):
        published = row.get("apparat_seal", "")
        recomputed_seal = compute_seal(
            row.get("context"),
            row.get("label"),
            row.get("source_url"),
            row.get("value"),
        )
        recomputed.append(recomputed_seal)
        if recomputed_seal != published:
            failures.append({
                "index": idx,
                "label": row.get("label", "(no label)"),
                "published": published,
                "recomputed": recomputed_seal,
            })
    return len(ledger) - len(failures), failures, recomputed


def verify_release(recomputed_seals, release):
    """
    Verify the release commitment (Merkle root) against the recomputed seals.
    Returns (ok: bool, computed_root, published_commitment).
    """
    published = release.get("release_commitment")
    computed = compute_merkle_root(recomputed_seals)
    return computed == published, computed, published


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Verify the integrity of a disclosure ledger (seals + release root)."
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--ledger", help="Path to local ledger.json")
    src.add_argument("--url", help="URL of a published ledger.json")
    ap.add_argument("--release", help="Path to local release.json (enables Merkle root check)")
    ap.add_argument("--release-url", help="URL of a published release.json")
    ap.add_argument("--quiet", action="store_true", help="Print only the final result line")
    args = ap.parse_args()

    # Load ledger
    try:
        ledger = load_json(args.ledger, args.url)
    except Exception as e:
        print(f"ERROR: could not load ledger: {e}", file=sys.stderr)
        return 2
    if not isinstance(ledger, list):
        print("ERROR: ledger.json must be a JSON array of records.", file=sys.stderr)
        return 2

    # Verify row seals
    ok_count, failures, recomputed = verify_rows(ledger)
    total = len(ledger)

    if not args.quiet:
        print(f"Disclosure Ledger Verifier")
        print(f"  Records:        {total}")
        print(f"  Seals verified: {ok_count}/{total}")
        if failures:
            print(f"  Seal failures:  {len(failures)}")
            for f in failures[:10]:
                print(f"    [row {f['index']}] {f['label'][:60]}")
                print(f"        published:  {f['published']}")
                print(f"        recomputed: {f['recomputed']}")
            if len(failures) > 10:
                print(f"    ... and {len(failures) - 10} more")

    # Optional: verify release commitment
    release = None
    release_ok = None
    if args.release or args.release_url:
        try:
            release = load_json(args.release, args.release_url)
        except Exception as e:
            print(f"ERROR: could not load release.json: {e}", file=sys.stderr)
            return 2
        release_ok, computed_root, published_root = verify_release(recomputed, release)
        if not args.quiet:
            print(f"  Release commitment:")
            print(f"    published:  {published_root}")
            print(f"    recomputed: {computed_root}")
            print(f"    {'OK — Merkle root matches' if release_ok else 'MISMATCH — root does not match'}")
            anchor = (release.get("anchor") or {})
            if anchor.get("rekor_entry_url"):
                print(f"  Anchor (Sigstore Rekor):")
                print(f"    status:     {release.get('anchor_status')}")
                print(f"    log index:  {anchor.get('rekor_log_index')}")
                print(f"    entry:      {anchor.get('rekor_entry_url')}")
                print(f"    (Rekor verification is an optional online step — see README.)")

    # Final verdict
    seals_pass = (len(failures) == 0)
    release_pass = (release_ok is not False)  # True or None(not requested) both acceptable
    overall = seals_pass and release_pass

    if overall:
        if release_ok is True:
            print(f"VERIFIED — {ok_count}/{total} rows intact, release commitment matches.")
        else:
            print(f"VERIFIED — {ok_count}/{total} rows intact and unaltered.")
        return 0
    else:
        print(f"FAILED — integrity check did not pass "
              f"({len(failures)} seal failure(s)"
              f"{', release root mismatch' if release_ok is False else ''}).")
        return 1


if __name__ == "__main__":
    sys.exit(main())
