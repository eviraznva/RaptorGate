#!/bin/bash
# Test scenariusza r1 -> RADIUS -> LDAP dla Issue 1.
set -u

LDAP_HOST="${LDAP_HOST:-192.168.20.40}"
RADIUS_HOST="${RADIUS_HOST:-192.168.20.30}"
RADIUS_SECRET="${RADIUS_SECRET:-radiussecret}"
BASE_DN="dc=raptorgate,dc=local"

fail=0

echo "== LDAP lookup ($LDAP_HOST) =="
for uid in admin user guest; do
  if ldapsearch -x -H "ldap://$LDAP_HOST" -b "$BASE_DN" "(uid=$uid)" uid 2>/dev/null | grep -q "^uid: $uid$"; then
    echo "  uid=$uid: OK"
  else
    echo "  uid=$uid: FAIL"
    fail=1
  fi
done

echo "== RADIUS Access-Accept ($RADIUS_HOST) =="
# Pary uid:haslo zgodne z seed.ldif.
for pair in admin:admin123 user:user123 guest:guest123; do
  uid="${pair%%:*}"
  pw="${pair##*:}"
  out=$(radtest "$uid" "$pw" "$RADIUS_HOST" 0 "$RADIUS_SECRET" 2>&1 || true)
  if echo "$out" | grep -q "Access-Accept"; then
    echo "  $uid: Access-Accept"
  else
    echo "  $uid: FAIL"
    echo "$out" | sed 's/^/    /'
    fail=1
  fi
done

echo "== RADIUS Access-Reject dla zlego hasla =="
out=$(radtest admin wrong-password "$RADIUS_HOST" 0 "$RADIUS_SECRET" 2>&1 || true)
if echo "$out" | grep -q "Access-Reject"; then
  echo "  admin/wrong-password: Access-Reject"
else
  echo "  admin/wrong-password: FAIL (oczekiwano Access-Reject)"
  echo "$out" | sed 's/^/    /'
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "== FAIL =="
  exit 1
fi
echo "== OK =="
