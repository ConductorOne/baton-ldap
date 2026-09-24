![Baton Logo](./docs/images/baton-logo.png)

# `baton-ldap` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-ldap.svg)](https://pkg.go.dev/github.com/conductorone/baton-ldap) ![ci](https://github.com/conductorone/baton-ldap/actions/workflows/ci.yaml/badge.svg) ![verify](https://github.com/conductorone/baton-ldap/actions/workflows/verify.yaml/badge.svg)

`baton-ldap` is a connector for LDAP built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the LDAP protocol to sync data about roles, users, and groups.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

## LDAP

## Credentials

To access the LDAP server, you must provide the username and password you use to login to the LDAP server.

# Getting Started

_Also see [Set up an LDAP connector](https://www.conductorone.com/docs/product/integrations/ldap/) in the ConductorOne documentation for instructions including using LDAP from ConductorOne._

## Installing

The latest release is available from the [`baton-ldap` Github releases page](https://github.com/ConductorOne/baton-ldap/releases).

Pre-built container images compatible with Docker and other container runtimes are [published to GHCR](https://github.com/ConductorOne/baton-ldap/pkgs/container/baton-ldap):
```
docker pull public.ecr.aws/conductorone/baton-ldap:latest
```

Additionally for testing on workstations, `baton-ldap` can be installed from Homebrew:
```
brew install conductorone/baton/baton conductorone/baton/baton-ldap
```

## Common Configuration Options

| CLI Flag | Environment Variable | Explaination |
|----------|----------|----------|
| `--bind-dn` | `BATON_BIND_DN` | **required** Username to bind to the LDAP server with, for example: `cn=baton-service-account,ou=users,dc=baton,dc=example,dc=com` |
| `--password` | `BATON_PASSWORD` | **optional**  Password to bind to the LDAP server with.  If unset, an unathenticated bind is attempted. |
| `--url` | `BATON_URL` | **required** URL to the LDAP server. Can be either `ldap:` or `ldaps:` schemes, sets the hostname, and optionally a port number. For example: `ldaps://ldap.example.com:636` |
| `--base-dn` | `BATON_BASE_DN`   |  **optional** Base Distinguished name to search for LDAP objects in, for example `DC=example,DC=com` |
| `--user-search-dn` | `BATON_USER_SEARCH_DN` |  **optional**  Distinguished name to search for User objects in.  If unset the Base DN is used. |
| `--group-search-dn` | `BATON_GROUP_SEARCH_DN` |  **optional**  Distinguished name to search for User objects in.  If unset the Base DN is used. |
| `--disable-user-attributes` | `BATON_DISABLE_USER_ATTRIBUTES` |  **optional** Map of LDAP attribute name to the value that marks an account as disabled, for example `--disable-user-attributes revoke=Y`. Unset by default. See [User enable/disable attributes](#user-enabledisable-attributes). |
| `--enable-user-attributes` | `BATON_ENABLE_USER_ATTRIBUTES` |  **optional** Map of LDAP attribute name to the value that marks an account as enabled, for example `--enable-user-attributes revoke=N`. Unset by default. When both directions are configured they must name the same attributes. |
| `--provisioning` | `BATON_PROVISIONING` |  **optional** Enable Provisioning of Groups by `baton-ldap`. `true` or `false`.  Defaults to `false` |
| `--group-member-attribute` | `BATON_GROUP_MEMBER_ATTRIBUTE` |  **optional** Which LDAP attribute to write group membership to: `auto` (default), `member`, `uniqueMember` or `memberUid`. See [Group membership attribute](#group-membership-attribute). |

Use `baton-ldap --help` to see all configuration flags and environment variables.

## User enable/disable attributes

Some directories mark an account's lifecycle state with their own attribute rather than the
standard `userAccountControl` (Active Directory) or `nsAccountLock` (FreeIPA) flags -- for example
IDMWorks uses `revoke`, with `Y` meaning disabled and `N` meaning enabled. Two optional maps
configure that definition:

```yaml
disable-user-attributes:
  revoke: "Y"
enable-user-attributes:
  revoke: "N"
```

- **Sync** reads both maps: an account is reported disabled when any configured attribute holds its
  disabled value, enabled when any holds its enabled value, and otherwise falls through to
  `userAccountControl` and `nsAccountLock`. Attribute values are compared case-insensitively and
  whitespace-trimmed, and a multi-valued attribute counts if any of its values matches.
- **`disable_user`** writes exactly the attributes named in `disable-user-attributes`; **`enable_user`**
  writes exactly those in `enable-user-attributes`. Neither action touches an attribute the other
  direction names.
- Because of that isolation, when both maps are configured they must name the **same** attributes --
  otherwise `enable_user` would leave an attribute at its disabled value and the synced status would
  disagree with the action's result forever. A configuration that names different attributes in each
  direction is rejected at startup. "Clear on enable" is written as an explicit empty value
  (`enable-user-attributes: {"revoke": ""}`), which keeps the attribute name present.
- The same attribute cannot carry the same value in both directions, attribute names must not be
  empty, neither `objectClass` nor any password attribute can be used as the marker, and the
  **disable** side cannot use an empty value; each is rejected at startup. The disable rule is not
  cosmetic: an absent attribute reads as enabled, so "disable by clearing the marker" would clear
  the attribute, report success, and leave sync reporting the account enabled forever. An empty
  value on the **enable** side stays legal -- that is clear-on-enable.
- Both maps are unset by default: a deployment that does not configure them behaves exactly as
  before. When only one direction is configured, only that action is registered on the connector.
- Attribute names are LDAP attribute names and are case-insensitive; names read from a config file
  are lowercased by the configuration library, which does not change the attribute written.
- **Quote the values.** The configuration loader stringifies map values before the connector sees
  them, so an unquoted `TRUE` or `FALSE` (`revoke: TRUE`) arrives as the string `"true"` and is
  written that way; LDAP's Boolean syntax (RFC 4517) requires uppercase, so the modify is rejected
  with an invalid-syntax error instead of setting the attribute. The connector cannot tell a quoted
  `"true"` from an unquoted one by then, so this is not caught at startup -- quote every value.
  `Y` and `N` are not YAML booleans and are safe unquoted.
- **As an environment variable, the value must be JSON.** A nested YAML map and repeated
  `--disable-user-attributes key=value` flags both work, but an environment variable arrives as a
  string: `BATON_DISABLE_USER_ATTRIBUTES='{"revoke":"Y"}'` is accepted, while
  `BATON_DISABLE_USER_ATTRIBUTES='revoke=Y'` is rejected at startup instead of silently configuring
  nothing.

## --create-account

To provision an account from the command line, you'll need to provide the login, email, and account profile. For example:

```
.\baton-ldap.exe --base-dn "DC=baton-dev,DC=d2,DC=ductone,DC=com" --password "password" -p --create-account-login 'example-user' --create-account-profile "{\"rdnKey\":\"uid\",\"path\":\"cn=staged users,cn=accounts,cn=provisioning\",\"suffix\":\"dc=example,dc=test\",\"objectClass\":[\"top\",\"person\",\"organizationalperson\",\"posixAccount\"],\"additionalAttributes\":{\"cn\":\"Example User\",\"sn\":\"User\",\"homeDirectory\":\"\",\"uidNumber\":\"-1\",\"gidNumber\":\"-1\"}}"'
```

# Actions

## `create_ou`

Creates an LDAP organizational unit (`organizationalUnit`) under a parent container.

| Argument | Required | Description |
|---|---|---|
| `name` | yes | The OU name. Used as the `ou` attribute and the RDN (`ou=<name>`). |
| `parent_dn` | no | The container DN to create the OU under. Defaults to the configured `base-dn`. |
| `description` | no | Sets the `description` attribute on the OU. |

Returns `ou_dn` (the created OU's DN) and `success`.

**Notes:**
- `base-dn` must be configured; the parent DN must be at or under it, or the action is rejected (fail-closed).
- The action is idempotent: creating an OU that already exists succeeds.
- The bind account must have permission to create entries at the target location.

## `update_profile`

Sets core profile fields (first name, last name, display name, email) and/or arbitrary
custom LDAP attributes on an existing user.

| Argument | Required | Description |
|---|---|---|
| `user_id` | yes | Account resource ID reference to the user to update. From a C1 automation this is the C1 account identifier, not the LDAP DN -- see the notes below. |
| `first_name` | no | The user's first (given) name, mapped to `givenName`. Ignored if empty. |
| `last_name` | no | The user's last (surname) name, mapped to `sn`. Ignored if empty. |
| `display_name` | no | The user's display name, mapped to `displayName`. Ignored if empty. |
| `email` | no | The user's email address, mapped to `mail`. Ignored if empty. |
| `custom_attributes` | no | Map of arbitrary raw LDAP attribute name → value, for attributes beyond the named fields above. Keys are used verbatim as attribute names. An empty value clears the attribute. |

Returns `success`, `updated_user` (the modified user resource, re-fetched after the
write; absent if the read-back failed, though the write itself still succeeded),
`applied` (the number of attributes modified), and `skipped` (named fields or
`custom_attributes` entries that were not written).

`updated_user` carries the resource identity, `displayName`, and the user trait -- not
the entry's full attribute set. A value the action just wrote appears there only when it
also feeds one of those: `display_name` through `displayName`, `email` through the
trait's email list, and a `custom_attributes` key only when it maps to a trait field
(`mail`, `displayName`, `sAMAccountName`, `userPrincipalName`, a non-RDN `uid` or `cn`,
`lastLogonTimestamp`, `authTimestamp`). `first_name`, `last_name`, and every other
`custom_attributes` key reach the directory but do not appear in `updated_user`. Use
`applied` to confirm those.

**Notes:**
- Scope: this action is **resource-scoped to `user`**. Resource-scoping is what makes
  `update_profile` discoverable and usable from ConductorOne's attribute-push-rule
  feature, since that feature offers actions per resource type rather than the
  connector's global action list.
- Named-field semantics: `first_name`, `last_name`, `display_name`, and `email` are only
  applied when present **and non-empty** -- they cannot be used to clear an attribute. A
  present-but-empty named field is dropped from the write and reported in `skipped`
  rather than silently vanishing.
- `inetOrgPerson` requirement: of the four named fields, only `last_name` (`sn`) is
  universal -- it's a MUST attribute of the base `person` object class. `first_name`
  (`givenName`, defined in RFC 4519), `display_name` (`displayName`, RFC 2798), and
  `email` (`mail`, RFC 4524) are permitted on an entry only by RFC 2798's
  `inetOrgPerson` object class; writing one of them to an entry that doesn't carry
  `inetOrgPerson` fails loudly with LDAP result code 65 ("Object Class Violation").
  This is safe -- the failure is atomic, with no partial write and no data corruption --
  but it means those three fields only work against `inetOrgPerson` entries.
- `custom_attributes` semantics: an entry is written whenever the key is present,
  including with an empty value, which clears the attribute.
- **`custom_attributes` keys are raw, and only the named fields are translated.** The
  four named arguments above are the only names mapped to a different LDAP attribute
  (`first_name` → `givenName`, and so on). A `custom_attributes` key is used verbatim as
  the attribute name, whatever it looks like: `{"user_id": "x"}` writes an attribute
  literally named `user_id` -- it does **not** write `uid`. A name your directory does
  not define is refused by the server, and the result code depends on the
  implementation: OpenLDAP returns 17 ("Undefined Attribute Type"), ApacheDS returns 16
  ("No Such Attribute").
  Likewise `login` and `path`, which are baton profile field names rather than LDAP
  attributes, are attempted as literal attribute names rather than skipped. Only the
  safety checks below still apply to `custom_attributes` entries; none of them changes
  the attribute you named.
- Collisions: a `custom_attributes` key is dropped -- never merged with, or silently
  overwriting, a named field's slot -- and reported once in `skipped` when it
  case-insensitively matches either one of the four named argument names (`first_name`,
  `last_name`, `display_name`, `email`), or the LDAP attribute a supplied named field is
  writing (`givenName`, `sn`, `displayName`, `mail`). The second case only applies when
  that named field was actually supplied and non-empty; otherwise
  `{"givenName": "Jane"}` is an ordinary raw write.
- The following are **not** modifiable and are rejected or skipped: password attributes
  (`userPassword` / anything containing `password` -- use credential rotation instead),
  `objectClass` (both rejected), and the user's RDN attribute (skipped -- renaming
  requires a ModifyDN).
- **Multi-valued attributes:** setting (not clearing) a value on an attribute that
  currently holds more than one value now returns an error instead of silently
  discarding the extra values. Clearing (an empty value) a multi-valued attribute is
  unaffected and still removes all values -- that remains an explicit, intentional
  "remove all values" operation.
- **Value types:** `custom_attributes` carries one string per attribute, so binary
  attributes (`jpegPhoto`, `userCertificate;binary`) and option-tagged attributes
  (`;lang-xx`) cannot be set through this action.
- Only entries within the configured `user-search-dn` (or `base-dn`) may be modified;
  out-of-scope or non-user DNs are rejected as "not found" (fail-closed).
- **From a C1 automation, `user_id` takes the C1 account identifier, not the LDAP DN.**
  C1 resolves the account to the connector's resource before dispatching the action. A
  DN fails inside C1 with `resource <dn> with type user was not found` and never reaches
  the connector, so it produces no connector log line and leaves the directory
  untouched.
- **An attribute push rule must map from a single-valued attribute.** The connector's
  user profile carries only attributes that hold exactly one value on the entry, so a
  multi-valued source resolves to nothing: the rule saves and enables, and each push
  reports zero attributes applied.
- **Actions are not gated by `--provisioning` / `BATON_PROVISIONING`.** That flag gates the
  provisioning surface -- grant, revoke, account create/delete, credential rotation -- and
  the SDK registers the action service outside it, so `update_profile` runs and writes with
  the flag unset. What the action does require is a bind account with permission to modify
  the target entry.

## `enable_user`

Marks a user account as enabled by writing the attributes configured in
[`--enable-user-attributes`](#user-enabledisable-attributes).

| Argument | Required | Description |
|---|---|---|
| `user_id` | yes | Account resource ID reference to the user to enable. From a C1 automation this is the C1 account identifier, not the LDAP DN -- see the notes under `update_profile`. |

Returns `success`, `status` (`"enabled"`), `applied` (the number of attributes modified; `0` means
the account was already enabled), and `updated_user` (the user resource re-fetched after the write;
absent if the resource could not be encoded, though the write itself still succeeded).

**Notes:**
- **Only the attributes named in `--enable-user-attributes` are written.** An attribute that only
  `--disable-user-attributes` names is left exactly as it is; the action never clears an attribute
  it was not configured to write.
- **Clearing on enable.** Configure an attribute with an empty value
  (`enable-user-attributes: {"revoke": ""}`) to remove the disabled marker rather than write a
  value. The account then reads as enabled by **fall-through**: no configured attribute matches its
  disabled value, so the connector uses its built-in rules, which default an unspecified status to
  enabled. "Enabled" here means "the disabled marker is not present", not "a positive value was
  written".
- Idempotent: an account already in the requested state succeeds with `applied: 0`. That check runs
  **before** the modify, so it also covers a marker attribute that is multi-valued -- an entry whose
  attribute already holds the requested value among several is reported as already in state rather
  than failing, which is what the synced status says about it too. (Modifying such an attribute to a
  value it does not already hold is still refused: replacing it with a single value would silently
  discard the others.)
- If a configured attribute cannot be written (it is the entry's RDN attribute, for example) the
  action fails with `FailedPrecondition` naming the attribute, on the first call and on every retry
  alike. That is an error rather than returned data, which is why there is no `skipped` field: it
  could never hold anything on a successful call.
- After writing, the connector re-reads the entry and verifies that the targeted attributes now hold
  their configured values (case-insensitive, whitespace-trimmed, any value of a multi-valued
  attribute) or are absent when they were cleared. A mismatch fails the action instead of reporting
  a success the directory does not reflect.
- The action is registered only when `--enable-user-attributes` is set, so C1 never offers a
  lifecycle action this deployment cannot carry out.
- Not gated by `--provisioning`. The bind account needs permission to modify the target entry.

## `disable_user`

Marks a user account as disabled by writing the attributes configured in
[`--disable-user-attributes`](#user-enabledisable-attributes).

| Argument | Required | Description |
|---|---|---|
| `user_id` | yes | Account resource ID reference to the user to disable. From a C1 automation this is the C1 account identifier, not the LDAP DN -- see the notes under `update_profile`. |

Returns `success`, `status` (`"disabled"`), `applied` (the number of attributes modified; `0` means
the account was already disabled), and `updated_user`.

**Notes:** every note above applies unchanged -- only `--disable-user-attributes`'s attributes are
written, the action is idempotent, an unwritable configured attribute fails the action on the first
call as well as every retry, the write is verified against the entry's actual attribute values, and
registration is conditional on `--disable-user-attributes` being set.

# Developing baton-ldap

## Group membership attribute

A group's membership can live in `member` (a DN), `uniqueMember` (a DN) or `memberUid` (a login
name). Which one it is cannot be decided from the entry's object classes: `posixGroup` is STRUCTURAL
under RFC 2307 (OpenLDAP's `nis.schema`, so `{posixGroup, groupOfNames}` is rejected there) but
AUXILIARY under rfc2307bis (which is what 389 DS ships by default since 1.4 and what FreeIPA uses),
and a client such as SSSD picks the attribute it reads with its own `ldap_schema` setting regardless
of what the server has loaded.

So the connector observes the group entry and lets the server be the authority:

1. **Read.** An entry carrying `groupOfURLs` is dynamic (its members come from `memberURL`) and is
   never written. Otherwise the entry's own values are examined: whichever membership attributes
   already hold values are the ones this directory uses, and all of them are maintained when the
   entry has diverged. Only when the entry holds no membership at all do the object classes decide,
   as an ordered guess: `groupOfUniqueNames` alone tries `uniqueMember` first, `posixGroup` without a
   DN group class tries `memberUid` first, everything else tries `member` first.
2. **Write.** One attribute per request, because an LDAP modify naming two attributes is rolled back
   as a whole when either value already exists. A rejected attribute (result 65 objectClassViolation
   or 17 undefinedAttributeType) is the entry's schema refusing it, and the next candidate is tried;
   "the value is already there" (20) is reported as `GrantAlreadyExists`, not as an error.
3. **Verify.** After a write, the entry is re-read **on the connection that accepted it** and the
   connector asks the same question sync asks -- would the read path report this principal as a
   member? A write the server accepted but the re-read cannot confirm is reported as a retryable
   error and is *not* followed by a write to another attribute, which would leave the principal in
   two places.

A revoke is different, deliberately. It deletes the **exact stored values** that hold the principal,
from **every** attribute that holds them, in one atomic request -- never from a guess, and never from
an attribute the operator pinned. If no attribute holds the principal, the connector checks two
memberships it cannot remove and reports them instead of a false success: a membership that comes
from the user's own `gidNumber` (the group is a primary group), and a membership inherited through a
nested group (the group is a member of this one). Otherwise the answer is `GrantAlreadyRevoked`.

Known limits:

- A directory with schema checking **off** never rejects anything, so step 2 learns nothing and the
  first candidate is used. OpenLDAP cannot disable schema checking (since 2.4 the directive is gone),
  so this only affects servers that can, such as 389 DS (`nsslapd-schemacheck`). Use the pin below.
- A hybrid entry carrying both `groupOfURLs` and a static group class keeps its existing behavior:
  with the exact spelling `groupOfURLs`, the entry is treated as dynamic on both the read and the
  write side; with a different spelling, as a static group. This change does not alter that.
- A membership attribute outside these three (a site-specific attribute) is invisible to sync and to
  provisioning alike.
- Nested groups are read (as expandable grants) and the inherited-membership guard covers a revoke of
  the expanded grant; the traversal that detects inheritance is depth-capped (5 levels) and
  lookup-capped (50 entries), and a search that stops at either bound is reported as an error rather
  than as "already revoked".
- Removing the last member of a `groupOfNames` can be rejected by the server (`member` is a MUST
  attribute of that class). That is unchanged.
- Role membership still writes through `baton-ldap`'s idempotent-error-swallowing modify path, so a
  role grant or revoke can still fail silently. Roles are not part of this behavior change.

### `--group-member-attribute`

| CLI Flag | Environment Variable | Explaination |
|----------|----------|----------|
| `--group-member-attribute` | `BATON_GROUP_MEMBER_ATTRIBUTE` | **optional** Which LDAP attribute to write group membership to: `auto` (default), `member`, `uniqueMember` or `memberUid`. Any other value is rejected at startup, so a typo cannot silently disable a pin. |

`auto` is the behavior described above. Pin it when the directory cannot be learned from -- for
example when schema checking is disabled, so nothing is ever rejected and the connector would use its
first candidate for an entry that shows no membership. The pin governs **grants only**: a new
membership is written to the pinned attribute and only that one, and a rejection of it is reported
rather than falling through to an attribute the operator did not choose. **Revokes ignore the pin**,
because deleting from an attribute that does not hold the value is exactly the failure the pin would
otherwise reintroduce.

# Developing baton-ldap

## How to test with Docker Compose
You can use [compose.yaml](./compose.yaml) to launch an LDAP server and a PHP LDAP admin server to interact with the LDAP server.

Run `docker-compose up` to launch the containers.

You can then access the PHP LDAP admin server at http://localhost:8080 and login with the admin credentials you provided in the docker-compose file.

username: `CN=admin,DC=example,DC=org`
password: `admin`

After you login you can create new resources to be synced by baton.

After creating new resources on the LDAP server, use the `baton-ldap` cli to sync the data from the LDAP server with the example command below.
`baton-ldap --base-dn dc=example,dc=org --bind-dn cn=admin,dc=example,dc=org --password admin --domain localhost`

After successfully syncing data, use the baton CLI to list the resources and see the synced data.
`baton resources`
`baton stats`

# Data Model

`baton-ldap` will fetch information about the following LDAP resources:

- Users
- Roles as `organizationalRole` in LDAP
- Groups as `groupOfNames`, `groupOfUniqueNames`, `groupOfURLs`, `posixGroup` or `group` in LDAP

`baton-ldap` will sync information only from under the base DN specified by the `--base-dn` flag in the configuration.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.
