![Baton Logo](./docs/images/baton-logo.png)

# `baton-ldap` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-ldap.svg)](https://pkg.go.dev/github.com/conductorone/baton-ldap) ![main ci](https://github.com/conductorone/baton-ldap/actions/workflows/main.yaml/badge.svg)

`baton-ldap` is a connector for LDAP built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the LDAP API to sync data about roles, users, and groups.

Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

## LDAP 

## Credentials

To access the API, you must provide the username and password you use to login to the LDAP server. 

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-ldap

BATON_PASSWORD=admin_pass BATON_BASE_DN=base_dn BATON_USER_DN=user_dn BATON_DOMAIN=ldap_url baton-ldap
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_TOKEN=token BATON_UNSAFE=true ghcr.io/conductorone/baton-ldap:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-ldap/cmd/baton-ldap@main

BATON_PASSWORD=admin_pass BATON_BASE_DN=base_dn BATON_USER_DN=user_dn BATON_DOMAIN=ldap_url baton-ldap
baton resources
```

# Data Model

`baton-ldap` will fetch information about the following LDAP resources:

- Users
- Roles as `organizationalRole` in LDAP
- Groups as `groupOfUniqueNames` in LDAP

`baton-ldap` will sync information only from under the base DN specified by the `--base-dn` flag in the configuration.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-ldap` Command Line Usage

```
baton-ldap

Usage:
  baton-ldap [flags]
  baton-ldap [command]

Available Commands:
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --base-dn string                The base DN used to specify where in the tree to sync resources under. ($BATON_BASE_DN)
      --client-id string              The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string          The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --domain                        The domain of the LDAP url. ($BATON_DOMAIN)
  -f, --file string                   The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
      --grant-entitlement string      The entitlement to grant to the supplied principal ($BATON_GRANT_ENTITLEMENT)
      --grant-principal string        The resource to grant the entitlement to ($BATON_GRANT_PRINCIPAL)
      --grant-principal-type string   The resource type of the principal to grant the entitlement to ($BATON_GRANT_PRINCIPAL_TYPE)
  -h, --help                          help for baton-ldap
      --log-format string             The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string              The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --password string               The password of the user to bind to. ($BATON_PASSWORD)
      --revoke-grant string           The grant to revoke ($BATON_REVOKE_GRANT)
      --user-dn string                The user DN for the user to bind to. i.e. cn=admin,dc=example,dc=org ($BATON_USER_DN)
  -v, --version                       version for baton-ldap

Use "baton-ldap [command] --help" for more information about a command.

```