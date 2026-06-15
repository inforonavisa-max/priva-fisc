#!/usr/bin/env bash
# PRIVA-FISC v0-A (Leo) — positive + 4 negative soundness tests, driven by `leo run`.
# ============================================================================
# Mirrors the Mina v0-A fixture discipline: one valid instance must PROVE, and a
# minimally-tampered instance must be REJECTED for each constraint C1–C4.
#
# SYNTHETIC DATA ONLY. A fresh synthetic authority account is generated per run;
# no private key is ever written to disk (keys live in shell variables only).
#
# Requires Leo 4.2.0 on PATH (or `LEO=/path/to/leo ./run_tests.sh`).
set -uo pipefail

LEO="${LEO:-leo}"
cd "$(dirname "$0")"   # leo/ project root

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1"; fail=$((fail+1)); }

# i-th `• <n>field` output value (1-based) from a `leo run` capture.
nth_field() { printf '%s\n' "$1" | grep -oE '[0-9]+field' | sed -n "${2}p"; }
sig_of()    { "$LEO" account sign --private-key "$1" -m "$2" 2>&1 | grep -oE 'sign1[0-9a-z]+' | head -1; }

# Witness struct literal from 12 positional fields.
mk_w() {
  printf '{ seller_tin: %s, buyer_id: %s, enc_datetime: %s, enc_invoice: %s, items: %s, margin: %s, vat_base: %s, vat_amount: %s, rate_bp: %s, total: %s, r: %s, salt: %s }' "$@"
}

# Public statement constants (synthetic). D is opaque (two limbs).
DHI=123field; DLO=456field
SIB='[1field,2field,3field,4field,5field,6field,7field]'
BITS='[false,false,false,false,false,false,false]'

run_prove() { # <authority> <root> <c> <witness> <sig> [siblings]
  local sib="${6:-$SIB}"
  "$LEO" run prove "$1" "$2" "$DHI" "$DLO" "$3" "$4" "$5" "$sib" "$BITS"
}

echo "== build =="
if "$LEO" build >/dev/null 2>&1; then ok "leo build"; else bad "leo build"; exit 1; fi

# ── Valid synthetic instance ────────────────────────────────────────────────
# VAT @ 21% (2100 bp): vat = floor((100000*2100 + 5000)/10000) = 21000, r = 5000,
# total = 121000. All amounts < 2^52.
W_VALID=$(mk_w 111111field 222222field 20260615field 4242field 777777field \
              5000u64 100000u64 21000u64 2100u64 121000u64 5000u64 999999field)

PREP=$("$LEO" run prepare "$DHI" "$DLO" "$W_VALID" "$SIB" "$BITS" 2>/dev/null)
C=$(nth_field "$PREP" 1); ROOT=$(nth_field "$PREP" 2); M=$(nth_field "$PREP" 3)

# Synthetic authority + attacker accounts (kept in shell vars only; never written).
AOUT=$("$LEO" account new 2>&1)
AUTH_PK=$(printf '%s\n' "$AOUT" | grep -oE 'APrivateKey1[0-9A-Za-z]+' | head -1)
AUTH_ADDR=$(printf '%s\n' "$AOUT" | grep -oE 'aleo1[0-9a-z]+' | head -1)
ATT_PK=$("$LEO" account new 2>&1 | grep -oE 'APrivateKey1[0-9A-Za-z]+' | head -1)

SIG=$(sig_of "$AUTH_PK" "$M")

echo "== POSITIVE: valid instance proves =="
if run_prove "$AUTH_ADDR" "$ROOT" "$C" "$W_VALID" "$SIG" >/dev/null 2>&1; then
  ok "valid instance → proof PASSES (C1–C5 satisfied)"
else
  bad "valid instance should PASS but was rejected"
fi

echo "== NEG-A (C1 signature): authority address with an attacker's signature =="
SIG_BAD=$(sig_of "$ATT_PK" "$M")
if run_prove "$AUTH_ADDR" "$ROOT" "$C" "$W_VALID" "$SIG_BAD" >/dev/null 2>&1; then
  bad "wrong signature should be REJECTED but passed"
else
  ok "wrong signature → REJECTED (C1)"
fi

echo "== NEG-B (C3 VAT): vat_amount/total off by 1 (round-half-up eq fails) =="
# total stays consistent (121001 == 100000+21001) so ONLY the VAT equation breaks.
W_BADVAT=$(mk_w 111111field 222222field 20260615field 4242field 777777field \
               5000u64 100000u64 21001u64 2100u64 121001u64 5000u64 999999field)
PREP2=$("$LEO" run prepare "$DHI" "$DLO" "$W_BADVAT" "$SIB" "$BITS" 2>/dev/null)
C2=$(nth_field "$PREP2" 1); ROOT2=$(nth_field "$PREP2" 2); M2=$(nth_field "$PREP2" 3)
SIG2=$(sig_of "$AUTH_PK" "$M2")
if run_prove "$AUTH_ADDR" "$ROOT2" "$C2" "$W_BADVAT" "$SIG2" >/dev/null 2>&1; then
  bad "wrong VAT should be REJECTED but passed"
else
  ok "wrong VAT → REJECTED (C3; C1/C2/C4 still satisfied)"
fi

echo "== NEG-C (C4 Merkle): a tampered sibling breaks the root =="
if run_prove "$AUTH_ADDR" "$ROOT" "$C" "$W_VALID" "$SIG" \
             '[99field,2field,3field,4field,5field,6field,7field]' >/dev/null 2>&1; then
  bad "wrong Merkle sibling should be REJECTED but passed"
else
  ok "wrong Merkle sibling → REJECTED (C4)"
fi

echo "== NEG-D (C2 isolated): tamper a commit-only field (buyer_id), keep valid c =="
# buyer_id enters ONLY the commitment — not M, not VAT, not the Merkle path — so with
# the valid c/root/m/sig kept fixed, ONLY commit_c(w)==c fails.
W_BADBUYER=$(mk_w 111111field 333333field 20260615field 4242field 777777field \
                  5000u64 100000u64 21000u64 2100u64 121000u64 5000u64 999999field)
if run_prove "$AUTH_ADDR" "$ROOT" "$C" "$W_BADBUYER" "$SIG" >/dev/null 2>&1; then
  bad "tampered buyer_id should be REJECTED but passed"
else
  ok "tampered buyer_id → REJECTED (C2 only; C1/C3/C4 satisfied)"
fi

echo
echo "== SUMMARY: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
