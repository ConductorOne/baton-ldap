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
docker pull ghcr.io/conductorone/baton-ldap:latest
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
| `--provisioning` | `BATON_PROVISIONING` |  **optional** Enable Provisioning of Groups by `baton-ldap`. `true` or `false`.  Defaults to `false` |

Use `baton-ldap --help` to see all configuration flags and environment variables.

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

## `update_user_attrs`

Sets or clears arbitrary LDAP attributes on an existing user. This action also backs
ConductorOne's "push profile" flow for LDAP users.

| Argument | Required | Description |
|---|---|---|
| `resource_id` | yes | The distinguished name (DN) of the user to update. |
| `attrs` | yes | A map of attribute name → value. An empty value clears the attribute. |
| `attrs_update_mask` | yes | The subset of attribute names in `attrs` to actually write. |
| `resource_type` | no | The resource type; always `user` for this action. |

Returns `success`, `applied` (the number of attributes modified), and `skipped` (mask
entries that were not written).

**Notes:**
- Scope: this action is for **generic** LDAP directories. Active Directory and FreeIPA
  have their own connectors (`baton-active-directory`, `baton-freeipa`).
- Only entries within the configured `user-search-dn` (or `base-dn`) may be modified;
  out-of-scope or non-user DNs are rejected as "not found" (fail-closed).
- Attribute values are set with a `Replace`; an empty value clears the attribute.
  Attributes are **single-valued** through this action (the `attrs` map holds one value
  per name); binary attributes are not supported.
- Re-runs are idempotent: attributes already holding the requested value (or already
  absent, for a clear) are left untouched and reported via `applied`.
- The following are **not** modifiable and are rejected or skipped: password attributes
  (`userPassword` / anything containing `password` — use credential rotation instead),
  `objectClass` (both rejected), and the user's RDN attribute (skipped — renaming
  requires a ModifyDN).
- Provisioning must be enabled (`--provisioning` / `BATON_PROVISIONING=true`) for actions
  to run, and the bind account must have permission to modify the target entry.

## `update_profile`

Sets core profile fields (first name, last name, display name, email) and/or arbitrary
custom LDAP attributes on an existing user.

| Argument | Required | Description |
|---|---|---|
| `user_id` | yes | Resource ID reference to the user to update. |
| `first_name` | no | The user's first (given) name, mapped to `givenName`. Ignored if empty. |
| `last_name` | no | The user's last (surname) name, mapped to `sn`. Ignored if empty. |
| `display_name` | no | The user's display name, mapped to `displayName`. Ignored if empty. |
| `email` | no | The user's email address, mapped to `mail`. Ignored if empty. |
| `custom_attributes` | no | Map of arbitrary raw LDAP attribute name → value, for attributes beyond the named fields above. An empty value clears the attribute. |

Returns `success`, `updated_user` (the user resource after the update, best-effort
re-fetched; absent if the read-back failed, though the write itself still succeeded),
`applied` (the number of attributes modified), and `skipped` (named fields or
`custom_attributes` entries that were not written).

**Notes:**
- Scope: this action is **resource-scoped to `user`**, as opposed to `update_user_attrs`,
  which is a global (connector-level) action. This distinction matters: resource-scoping
  is what makes `update_profile` discoverable and usable from ConductorOne's
  attribute-push-rule feature, since that feature offers actions per resource type rather
  than the connector's global action list.
- Named-field semantics: `first_name`, `last_name`, `display_name`, and `email` are only
  applied when present **and non-empty** -- they cannot be used to clear an attribute. A
  present-but-empty named field is dropped from the write and reported in `skipped`
  rather than silently vanishing.
- `custom_attributes` semantics: an entry is written whenever the key is present,
  including with an empty value (which clears the attribute) -- consistent with
  `update_user_attrs`'s "empty value clears" rule.
- Collisions: a `custom_attributes` key that case-insensitively matches one of the four
  named argument names (`first_name`, `last_name`, `display_name`, `email`) is dropped --
  never merged with, or silently overwriting, the named field's slot -- and reported
  once in `skipped`.
- The same restrictions as `update_user_attrs` apply: password attributes
  (`userPassword` / anything containing `password` -- use credential rotation instead),
  `objectClass` (both rejected), and the user's RDN attribute (skipped) cannot be
  modified through this action.
- **Multi-valued attributes:** setting (not clearing) a value on an attribute that
  currently holds more than one value now returns an error instead of silently
  discarding the extra values. Clearing (an empty value) a multi-valued attribute is
  unaffected and still removes all values -- that remains an explicit, intentional
  "remove all values" operation.
- Only entries within the configured `user-search-dn` (or `base-dn`) may be modified;
  out-of-scope or non-user DNs are rejected as "not found" (fail-closed), same as
  `update_user_attrs`.
- Provisioning must be enabled (`--provisioning` / `BATON_PROVISIONING=true`) for actions
  to run, and the bind account must have permission to modify the target entry.

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
- Groups as `groupOfUniqueNames` in LDAP

`baton-ldap` will sync information only from under the base DN specified by the `--base-dn` flag in the configuration.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.
