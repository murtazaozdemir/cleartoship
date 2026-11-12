#!/usr/bin/env bash
# Rule 26 step 6: no NEW source file over 500 lines, and no allowlisted file
# grows past the size it was when it went on the list.
#
# The allowlist is the half that makes this adoptable. Ten files here are
# already over the line and are not being split today (TODO.md says why, and
# tracks the one genuine split as a planned refactor). A bare 500-line check
# would be red on arrival and would get ignored -- the always-red-gate failure
# mode another app in this portfolio pinned its dependency-audit gate at
# `critical` to avoid. So: pin them, and ratchet.
#
# Scope is tracked, first-party source. Deliberately excluded, each for a
# reason rather than for convenience:
#   src/vendor/      vendored upstream, kept as a faithful copy -- re-vendoring
#                    is a straight overwrite, so splitting it is not an option
#   test/fixtures/   deliberately-vulnerable bait; its shape is dictated by
#                    what the rules have to detect, not by readability
#   dist/ standalone/ build output (and gitignored)
#   *-lock.json      generated dependency trees
#   *.md             prose; TODO.md is a chronological narrative on purpose
# A gitignored file cannot fail this gate, because it is not tracked -- which
# is also why `marketing.html` is absent.
#
# Usage: check-file-sizes.sh [--update]
#   --update rewrites the ceilings to the measured sizes. Use it after a
#   deliberate refactor; it is not a way to make a failure go away, and the
#   diff it produces is meant to be read in review.
set -euo pipefail
cd "$(dirname "$0")/.."

LIMIT=500
LIST=scripts/file-size-ceilings.txt
update=0
[ "${1-}" = "--update" ] && update=1

# `wc -l` counts newlines, so a file with no trailing newline reads one short.
lines() { awk 'END { print NR }' "$1"; }

sources() {
  git ls-files -- 'src/**' 'test/**' 'site/**' 'scripts/**' \
    ':!:src/vendor/**' ':!:test/fixtures/**' ':!:**/*-lock.json' ':!:**/*.md'
}

declare -a over=()            # path:size, everything currently over the limit
while IFS= read -r f; do
  [ -f "$f" ] || continue
  n=$(lines "$f")
  [ "$n" -gt "$LIMIT" ] && over+=("$f:$n")
done < <(sources)

ceiling_of() { awk -v want="$1" '!/^#/ && NF==2 && $2==want { print $1; found=1 } END { if (!found) print "" }' "$LIST"; }

if [ "$update" = 1 ]; then
  { sed -n '1,/^[0-9]/{/^[0-9]/!p;}' "$LIST"
    for row in "${over[@]}"; do echo "${row##*:} ${row%:*}"; done | sort -rn
  } > "$LIST.tmp"
  mv "$LIST.tmp" "$LIST"
  echo "ceilings updated to the measured sizes of ${#over[@]} file(s); read the diff"
  exit 0
fi

fail=0
for row in "${over[@]}"; do
  f=${row%:*}; n=${row##*:}
  ceiling=$(ceiling_of "$f")
  if [ -z "$ceiling" ]; then
    echo "::error file=${f}::${f} is ${n} lines, over the ${LIMIT}-line limit, and is not on the allowlist. Rule 26 step 1: split it by responsibility. If it genuinely is one job, add it to ${LIST} in the same commit and say why in TODO.md."
    fail=1
  elif [ "$n" -gt "$ceiling" ]; then
    echo "::error file=${f}::${f} grew to ${n} lines, past its ceiling of ${ceiling}. An allowlisted file may shrink, not grow -- move what you added into a new file, or split the file now."
    fail=1
  elif [ "$n" -lt "$ceiling" ]; then
    echo "::notice file=${f}::${f} is ${n} lines, $((ceiling - n)) under its ceiling of ${ceiling} -- tighten it in ${LIST} (or run scripts/check-file-sizes.sh --update) so the ratchet holds."
  fi
done

# A row for a file that is gone, renamed, or now back under the limit is the
# other way this list rots. Report it; do not fail on good news.
while read -r ceiling f; do
  case "$ceiling" in ''|\#*) continue ;; esac
  if [ ! -f "$f" ]; then
    echo "::notice::${LIST} still pins ${f}, which no longer exists -- drop the row."
  else
    n=$(lines "$f")
    [ "$n" -le "$LIMIT" ] && echo "::notice::${f} is back under ${LIMIT} lines (${n}) -- drop its row from ${LIST}."
  fi
done < <(grep -vE '^\s*(#|$)' "$LIST")

if [ "$fail" = 1 ]; then
  exit 1
fi
echo "${#over[@]} source file(s) over ${LIMIT} lines, all allowlisted and none above its ceiling"
