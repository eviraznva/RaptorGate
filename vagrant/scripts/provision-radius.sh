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
    server = "192.168.2.20"
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

# --- Configure RADIUS client (allow entire 192.168.2.0/24 subnet) ---
cat >> "$FR/clients.conf" <<'CLIENTS'

client ngfw_network {
    ipaddr = 192.168.2.0/24
    secret = radiussecret
    shortname = ngfw-lan
}
CLIENTS

# --- Enable LDAP in authorize (default + inner-tunnel) ---
# Add "ldap" before first occurrence of "pap" (which is in authorize section)
perl -i -0pe 's/(\n\s*pap\n)/\n\t\tldap$1/' "$FR/sites-available/default"
perl -i -0pe 's/(\n\s*pap\n)/\n\t\tldap$1/' "$FR/sites-available/inner-tunnel"

systemctl restart freeradius
systemctl enable freeradius

echo "=== FreeRADIUS setup complete ==="
echo "Shared secret: radiussecret"
echo "Testing LDAP user 'admin'..."
radtest admin admin123 127.0.0.1 0 testing123 || echo "(test may fail if localhost client uses different secret)"