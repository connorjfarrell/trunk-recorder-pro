#!/usr/bin/env bash
# Checks that nothing from a live radio system has been committed: key containers and password
# files, recordings and captures, call records (talkgroups, radio IDs), talkgroup and unit-alias
# exports, config files naming a real system's channels, recorder log lines, key-length hex
# strings, private addresses and home-directory paths.
#
# It reads what the branch ADDED (every commit in the range, not just the final files) and the
# names of the tracked files. Usage:
#
#   scripts/check-live-data.sh [--range <git rev range>] [--denylist <file>]
#
# --range    default: origin/main..HEAD, else main..HEAD, else all of history.
# --denylist a file of your own terms that must never appear (system and site names, NAC / WACN /
#            system IDs, key IDs, talkgroup names, radio IDs, unit aliases, hostnames, serial
#            numbers). One per line: plain text (any case), or `re:<regex>`; `#` starts a comment.
#            Also read from the environment variable LIVE_DATA_DENYLIST (the same lines), which is
#            how CI gets it, from a repository secret. KEEP THAT FILE OUT OF THE REPOSITORY: it is
#            the list of the very things that mustn't be in it. A match is reported by file and
#            line and the number of the entry, never the text, so a public CI log doesn't repeat it.
#
# Known harmless values (the standards' published test vectors, documentation addresses) are in
# .live-data-allow: one extended regex per line, matched against the added line.
# Exit status 1 when anything is found.

set -u
cd "$(git rev-parse --show-toplevel)" || exit 2

range=""
deny_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --range) range="$2"; shift 2 ;;
    --denylist) deny_file="$2"; shift 2 ;;
    *) echo "usage: $0 [--range <rev range>] [--denylist <file>]" >&2; exit 2 ;;
  esac
done
if [ -z "$range" ]; then
  if git rev-parse -q --verify origin/main >/dev/null; then range="origin/main..HEAD"
  elif git rev-parse -q --verify main >/dev/null; then range="main..HEAD"
  else range="HEAD"; fi
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fail=0
problem() { echo "::error::$*"; echo "FOUND: $*"; fail=1; }

# ── What was added: "<file>\t<line>" for every added line in the range ──────────────────────────
git log -p --no-color --format= -U0 "$range" -- . ':!Cargo.lock' ':!web/package-lock.json' | awk '
  /^\+\+\+ b\// { f = substr($0, 7); next }
  /^\+\+\+ /    { f = ""; next }
  /^\+/         { print f "\t" substr($0, 2) }' > "$tmp/added.tsv"
git log --no-color --format='(commit message)%x09%B' "$range" > "$tmp/messages.tsv"

# Lines the allowlist says are harmless.
allow="$tmp/allow.txt"
grep -v -E '^\s*(#|$)' .live-data-allow 2>/dev/null > "$allow" || : > "$allow"
dropped_allowed() { if [ -s "$allow" ]; then grep -v -E -f "$allow"; else cat; fi; }

# rule <name> <only paths ERE> <except paths ERE> <line ERE>
rule() {
  local name="$1" only="$2" except="$3" re="$4"
  awk -F'\t' -v only="$only" -v except="$except" '
    $1 ~ only && !(except != "" && $1 ~ except) { print $1 ": " substr($0, length($1) + 2) }' "$tmp/added.tsv" | { grep -E -e "$re" || true; } | dropped_allowed > "$tmp/hits.txt"
  if [ -s "$tmp/hits.txt" ]; then
    problem "$name"
    cut -c1-200 "$tmp/hits.txt" | head -5 | sed 's/^/    /'
  fi
}

DATA='\.(json|jsonl|txt|log|csv|conf|ya?ml|toml|cfg|ini)$'
DOCS='^(docs/|README|CHANGELOG)'
NOTCONFIGS='^(docs/|web/(src|scripts|package)|\.github/|\.coderabbit|\.gitleaks|.*registry\.json|.*tsconfig|.*\.schema\.json|Cargo\.toml$|.*/Cargo\.toml$|rustfmt|clippy|deny)'

# ── Names of tracked files ──────────────────────────────────────────────────────────────────────
bad=$(git ls-files | grep -E '\.(ekc|pw|cu8|s16|cf32|sdr|wav|m4a|bandplan)$|\.frames\.jsonl$|units\.csv$|(^|/)calls(/|$)|(^|/)config\.json$' | grep -v '^crates/trunk-core/src/crypto/testdata/dummy-test-keys\.ekc$' || true)
if [ -n "$bad" ]; then
  problem "tracked files that are keys, recordings, captures, configs or unit lists (they belong outside the repository):"
  echo "$bad" | sed 's/^/    /'
fi

# ── Heuristics over the added lines ─────────────────────────────────────────────────────────────
rule "a recorder log line (talkgroup and frequency)" '.*' "$DOCS|^crates/.*/(tests?|testdata)/" 'TG:[[:space:]]+[0-9]+[[:space:]]+Freq:[[:space:]]+[0-9]+\.[0-9]+[[:space:]]+MHz'
rule "a talkgroup export (RadioReference, Trunk Recorder CSV)" '.*' "$DOCS" '(Decimal,Hex,Mode,Alpha Tag|DEC[[:space:]]+HEX[[:space:]]+MODE[[:space:]]+ALPHA TAG)'
rule "a call record (talkgroup, radio ids)" "$DATA" '^docs/' '"(srcList|src|unit|radio_id|unitId|talkgroup)"[[:space:]]*:[[:space:]]*(\[|[0-9]{3,})'
rule "a config naming real channels, keys or files" "$DATA" "$NOTCONFIGS" '"(controlChannelsHz|voiceChannelsHz|talkgroupsCsv|ekcFile|passwordFile|apiKey|systemName|shortName)"[[:space:]]*:[[:space:]]*(\[[[:space:]]*[0-9]|"[^"]+")'
rule "a unit alias or radio name list" "$DATA" '^docs/' ': [0-9]{5,9},[^,]*[A-Za-z]'
rule "a key-length hex string (16 bytes or more)" '.*' '' '(^|[^0-9A-Za-z])[0-9A-Fa-f]{32,}($|[^0-9A-Za-z])'
rule "a RadioReference system link" '.*' '' 'radioreference\.com/db/sid/[0-9]+'
rule "a private address" '.*' '' '(^|[^0-9.])(10(\.[0-9]{1,3}){3}|192\.168(\.[0-9]{1,3}){2}|172\.(1[6-9]|2[0-9]|3[01])(\.[0-9]{1,3}){2})($|[^0-9])'
rule "a home-directory path" '.*' '' '(/Users/|/home/)[A-Za-z0-9._-]+'
rule "a SDR serial number or MAC address" '.*' '' '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|[Ss]erial[^A-Za-z0-9]{1,4}0?x?[0-9A-Fa-f]{16}($|[^0-9A-Za-z])'

# ── Your own terms ──────────────────────────────────────────────────────────────────────────────
{ [ -n "$deny_file" ] && cat "$deny_file"; printf '%s\n' "${LIVE_DATA_DENYLIST:-}"; } | grep -v -E '^\s*(#|$)' > "$tmp/deny.txt" || true
n=0
terms=0
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  n=$((n + 1)); terms=$n
  if [ "${entry#re:}" != "$entry" ]; then re="${entry#re:}"; opt=(-E -i); else re="$entry"; opt=(-F -i); fi
  # (names of tracked files, added lines, commit messages)
  if git ls-files | grep "${opt[@]}" -q -e "$re"; then problem "denylist entry #$n appears in the name of a tracked file"; fi
  if cut -f2- "$tmp/added.tsv" | grep "${opt[@]}" -q -e "$re"; then
    problem "denylist entry #$n appears in added lines:"
    awk -F'\t' '{print NR "\t" $0}' "$tmp/added.tsv" | grep "${opt[@]}" -e "$re" | head -5 | awk -F'\t' '{print "    " $2 ": (line " $1 " of the added lines)"}'
  fi
  if grep "${opt[@]}" -q -e "$re" "$tmp/messages.tsv"; then problem "denylist entry #$n appears in a commit message"; fi
done < "$tmp/deny.txt"
if [ "$terms" -eq 0 ]; then
  echo "note: no denylist given (--denylist or LIVE_DATA_DENYLIST): only the general checks ran."
else
  echo "denylist: $terms entr$([ "$terms" -eq 1 ] && echo y || echo ies) checked."
fi

if [ "$fail" -eq 0 ]; then
  echo "check-live-data: nothing found in $range ($(wc -l < "$tmp/added.tsv" | tr -d ' ') added lines)."
fi
exit "$fail"
