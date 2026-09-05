#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
cd "$root"

command -v rg >/dev/null 2>&1 || {
  echo "public-repo: ripgrep (rg) is required" >&2
  exit 1
}

tracked_files=()
public_files=()
while IFS= read -r -d '' file; do
  tracked_files+=("$file")
  case "$file" in
    README.md|MIGRATION.md|ARCHITECTURE.md|config.example.yaml|configs/*|contrib/*|docs/*)
      public_files+=("$file")
      ;;
  esac
done < <(git ls-files -z)

(( ${#tracked_files[@]} > 0 )) || { echo "public-repo: no tracked files found"; exit 0; }
fail=0
report() { echo "public-repo: $*" >&2; fail=1; }

# Keep marker fragments separate in this script so the repo-wide scanner does
# not match its own rule source.
pem_pattern="-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
if pem_hits=$(rg -n -I -- "$pem_pattern" "${tracked_files[@]}" 2>/dev/null); then
  printf '%s\n' "$pem_hits"
  report "repo-wide private-key marker found"
fi

# These are high-confidence Go x509 encodings used by this project, not a
# generic entropy rule. Public PKIX/SPKI keys use a different prefix.
sec1_pattern="MHcCAQ"'EEI[A-Za-z0-9+/=]{60,}'
pkcs8_pattern="MIGHAgEAMBMGByqGSM49"'AwE[A-Za-z0-9+/=]{20,}'
der_hits=$(rg -n -I -o -- "$sec1_pattern|$pkcs8_pattern" "${tracked_files[@]}" 2>/dev/null || true)
if [[ -n "$der_hits" ]]; then
  printf '%s\n' "$der_hits"
  report "repo-wide Base64 DER EC private-key material found"
fi

if (( ${#public_files[@]} > 0 )); then
  domain_hits=$(rg -n -I -o -- '([[:alnum:]-]+\.)+(com|net|org|top|cn|io|dev|app|xyz|info|site|online|cloud)' "${public_files[@]}" | \
    rg -v '(example\.(com|net|org)|localhost|proxy\.test|target\.test|github\.com|golang\.org|pkg\.go\.dev|metacubex\.com)([^[:alpha:]]|$)' || true)
  if [[ -n "$domain_hits" ]]; then
    printf '%s\n' "$domain_hits"
    report "non-example domain found in public docs/configuration"
  fi

  ip_hits=$(rg -n -I -o -- '(^|[^0-9])(([0-9]{1,3}\.){3}[0-9]{1,3})(/[0-9]{1,2})?([^0-9]|$)' "${public_files[@]}" | \
    sed -E 's/.*[^0-9](([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?).*/\1/' | sort -u || true)
  while IFS= read -r cidr; do
    [[ -z "$cidr" ]] && continue
    ip=${cidr%%/*}; IFS=. read -r a b c d <<< "$ip"
    if ((a == 127 || a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) || (a == 192 && b == 0 && c == 2) || (a == 198 && b == 51 && c == 100) || (a == 203 && b == 0 && c == 113))); then
      continue
    fi
    report "public IPv4 found: $cidr"
  done <<< "$ip_hits"

  if ipv6_hits=$(rg -n -I -o -- '([0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{1,4}(/[0-9]{1,3})?' "${public_files[@]}" | \
    rg -v '(^|[^0-9A-Fa-f])(::1|fe80:|fc[0-9A-Fa-f]{2}:|fd[0-9A-Fa-f]{2}:|2001:db8:)' ); then
    printf '%s\n' "$ipv6_hits"
    report "non-example IPv6 found in public docs/configuration"
  fi
fi

if ((fail)); then exit 1; fi
echo "public-repo: repo-wide secret and public-surface privacy checks passed"
