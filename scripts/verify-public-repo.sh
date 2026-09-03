#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

files=()
while IFS= read -r file; do files+=("$file"); done < <(git ls-files -- README.md MIGRATION.md ARCHITECTURE.md config.example.yaml 'configs/**' 'contrib/**')
(( ${#files[@]} > 0 )) || { echo "public-repo: no public files found"; exit 0; }
fail=0
report() { echo "public-repo: $*" >&2; fail=1; }

if rg -n -I -- '-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|-----BEGIN PRIVATE KEY-----' "${files[@]}"; then
  report "private-key marker found"
fi

domain_hits=$(rg -n -I -o -- '([[:alnum:]-]+\.)+(com|net|org|top|cn|io|dev|app|xyz|info|site|online|cloud)' "${files[@]}" | \
  rg -v '(example\.(com|net|org)|localhost|proxy\.test|target\.test|github\.com|golang\.org|pkg\.go\.dev|metacubex\.com)([^[:alpha:]]|$)' || true)
if [[ -n "$domain_hits" ]]; then
  printf '%s\n' "$domain_hits"
  report "non-example domain found in public docs/configuration"
fi

ip_hits=$(rg -n -I -o -- '(^|[^0-9])(([0-9]{1,3}\.){3}[0-9]{1,3})(/[0-9]{1,2})?([^0-9]|$)' "${files[@]}" | \
  sed -E 's/.*[^0-9](([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?).*/\1/' | sort -u || true)
while IFS= read -r cidr; do
  [[ -z "$cidr" ]] && continue
  ip=${cidr%%/*}; IFS=. read -r a b c d <<< "$ip"
  if ((a == 127 || a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113))); then
    continue
  fi
  report "public IPv4 found: $cidr"
done <<< "$ip_hits"

if rg -n -I -o -- '([0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{1,4}(/[0-9]{1,3})?' "${files[@]}" | \
  rg -v '(^|[^0-9A-Fa-f])(::1|fe80:|fc[0-9A-Fa-f]{2}:|fd[0-9A-Fa-f]{2}:|2001:db8:)'; then
  report "non-example IPv6 found in public docs/configuration"
fi

if ((fail)); then exit 1; fi
echo "public-repo: privacy checks passed"
