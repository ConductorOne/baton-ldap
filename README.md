![Baton Logo](./docs/images/baton-logo.png)

# `baton-ldap` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-ldap.svg)](https://pkg.go.dev/github.com/conductorone/baton-ldap) ![main ci](https://github.com/conductorone/baton-ldap/actions/workflows/main.yaml/badge.svg)

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
