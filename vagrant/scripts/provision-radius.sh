#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y freeradius freeradius-ldap

# Stop freeradius during config
systemctl stop freeradius

FR="/etc/freeradius/3.0"

# --- Configure LDAP module ---
cat > "$FR/mods-available/ldap" <<'LDAPCONF'
ldap {
    server = "192.168.20.40"
    port = 389
    identity = "cn=admin,dc=raptorgate,dc=local"
    password = admin
    base_dn = "dc=raptorgate,dc=local"

    update {
        control:Password-With-Header += "userPassword"
        control:NT-Password := "sambaNTPassword"
    }

    user {
        base_dn = "ou=users,${..base_dn}"
        filter = "(uid=%{%{Stripped-User-Name}:-%{User-Name}})"
    }

    group {
        base_dn = "ou=groups,${..base_dn}"
        filter = "(objectClass=posixGroup)"
        membership_attribute = "memberUid"
    }
}
LDAPCONF

# Enable LDAP module
ln -sf ../mods-available/ldap "$FR/mods-enabled/ldap"

# --- Configure RADIUS client (allow entire 192.168.20.0/24 subnet) ---
# Idempotent: usun istniejacy blok ngfw_network (z dowolnego wczesniejszego runu) i dodaj raz.
perl -i -0pe 's/\n*client ngfw_network\s*\{[^}]*\}\n*/\n/g' "$FR/clients.conf"
cat >> "$FR/clients.conf" <<'CLIENTS'

client ngfw_network {
    ipaddr = 192.168.20.0/24
    secret = radiussecret
    shortname = ngfw-lan
}
CLIENTS

# --- Enable LDAP in authorize (default + inner-tunnel) ---
# Idempotent: najpierw usun wszystkie samodzielne linie 'ldap' poprzedzajace 'pap'
# (ewentualne duplikaty z poprzednich runow), potem wstaw raz przed pierwszym 'pap'.
for site in default inner-tunnel; do
  perl -i -0pe 's/(?:\n\s*ldap)+(\n\s*pap\n)/$1/g' "$FR/sites-available/$site"
  perl -i -0pe 's/(\n\s*pap\n)/\n\t\tldap$1/' "$FR/sites-available/$site"
done

systemctl restart freeradius
systemctl enable freeradius

echo "=== FreeRADIUS setup complete ==="
echo "Shared secret: radiussecret"

# Smoke test prowizji: uderz w radiusa z jego wlasnego IP 192.168.20.30 —
# source pasuje do subnetu 192.168.20.0/24 z client ngfw_network, wiec testujemy
# nasz wpis klienta i subnet (line 48), nie default 'localhost/testing123'.
# Bez maskowania wyniku — prowizja musi fail-fast gdy flow radius -> ldap jest zepsuty.
echo "Testing ngfw_network client via 192.168.20.30 (admin/admin123)..."
radtest admin admin123 192.168.20.30 0 radiussecret | tee /tmp/radtest.out
grep -q "Access-Accept" /tmp/radtest.out