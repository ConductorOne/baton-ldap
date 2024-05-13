#!/usr/bin/env node

// Usage: node ldif.js
// Script to generate a bunch of ldap users/groups for testing.
// This will generate big-*.ldif in the current directory, which you can import into openldap.
const fs = require('node:fs');

const userCount = 1000;
const groupCount = 50;
const maxFileSize = 2000000; // php ldap admin has a 2MB limit

let fileSize = 0;
let fileCount = 0;
const baseFileName = "big-";

let f;
// Only pass strings that constitute full objects to write().
// Otherwise the object will span across multiple files and import will fail.
function write (data, opts = {}) {
  fileSize += data.length;
  if (fileSize > maxFileSize) {
    fs.closeSync(f);
    fileSize = data.length;
    fileCount++;
    f = null;
  }

  const filename = `${baseFileName}${("0000" + fileCount).slice(-5)}.ldif`;
  if (!f) {
    f = fs.openSync(filename, 'w');
  }
  fs.appendFileSync(filename, data, opts);
}


// Org
// Uncomment this if your ldap server doesn't auto-create an org
/*
write(`dn: dc=example,dc=org
dc: example
o: example
objectclass: top
objectclass: dcObject
objectclass: organization

`);
*/

// Posix groups
for (let groupId = 0; groupId < groupCount; groupId++) {
  const groupIdStr = ("0000" + groupId).slice(-5);
  let groupStr = `dn: cn=testgroup${groupIdStr},dc=example,dc=org
objectClass: top
objectClass: posixGroup
cn: testgroup${groupIdStr}
gidNumber: ${groupId}
`;

  for (let userId = 0; userId < userCount; userId++) {
    const userIdStr = ("00000" + userId).slice(-5);
    groupStr += `memberuid: testuser${userIdStr}
`;
  }

  write(groupStr + "\n");
}

// Non-posix groups
for (let groupId = 0; groupId < groupCount; groupId++) {
  const groupIdStr = ("0000" + groupId).slice(-5);
  let groupStr = `dn: cn=othertestgroup${groupIdStr},dc=example,dc=org
objectClass: top
objectClass: groupOfUniqueNames
cn: othertestgroup${groupIdStr}
owner: cn=testuser00000,dc=example,dc=org
`;

  for (let userId = 0; userId < userCount; userId++) {
    const userIdStr = ("00000" + userId).slice(-5);
    groupStr += `uniquemember: cn=testuser${userIdStr},dc=example,dc=org
`;
  }

  write(groupStr + "\n");
}

// Users
for (let userId = 0; userId < 5000; userId++) {
    const userIdStr = ("00000" + userId).slice(-5);
    write(`dn: cn=testuser${userIdStr},dc=example,dc=org
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
telephoneNumber: +1509555${userIdStr}
uid: testuser${userIdStr}
sn: testuser${userIdStr}
givenName: test
cn: testuser${userIdStr}
displayName: test
uidNumber: ${(10000 + userId).toString()}
gidNumber: 500
gecos: Test User ${userIdStr}
loginShell: /bin/bash
homeDirectory: /home/testuser${userIdStr}
title: Test*User ${userIdStr}

`);
}
