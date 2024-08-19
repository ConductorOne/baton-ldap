#!/usr/bin/env bash

set -euxo pipefail


for filename in big-*.ldif; do
  [ -e "$filename" ] || continue
  ldapadd -D 'CN=admin,DC=example,DC=org' -N -x -H 'ldap://localhost:389/' -w admin -f "$filename"
done
