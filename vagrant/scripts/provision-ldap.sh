#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

# ip route add default dev eth0 || true 
apt-get update
apt-get install -y slapd ldap-utils
# ip route del default dev eth0 || true

# Preseed slapd config
debconf-set-selections <<EOF
slapd slapd/internal/generated_adminpw password admin
slapd slapd/internal/adminpw password admin
slapd slapd/password1 password admin
slapd slapd/password2 password admin
slapd slapd/domain string raptorgate.local
slapd shared/organization string RaptorGate
slapd slapd/purge_database boolean true
slapd slapd/move_old_database boolean true
slapd slapd/no_configuration boolean false
EOF

# Wait for slapd to be ready
systemctl restart slapd
sleep 2

# Seed data — ldapadd -c kontynuuje przy błędzie "Already exists"
ldapadd -c -x -D "cn=admin,dc=raptorgate,dc=local" -w admin -f /tmp/seed.ldif || true

echo "=== LDAP setup complete ==="
echo "Base DN: dc=raptorgate,dc=local"
echo "Admin DN: cn=admin,dc=raptorgate,dc=local"
echo "Admin password: admin"
ldapsearch -x -b "dc=raptorgate,dc=local" "(objectClass=*)" dn
