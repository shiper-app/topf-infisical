# topf-infisical

An Infisical secrets provider for [TOPF](https://github.com/postfinance/topf),
modeled after topf-openbao. Uses Go's standard library; the Infisical CLI is
only required when using an existing interactive login.

## Build

Requires Go 1.22 or newer.

```sh
go build -trimpath -o topf-infisical .
go test -race ./...
```

In your `topf.yaml`:

```yaml
secretsProvider: /home/rebertim/Projects/topf-infisical/topf-infisical
```

## Configure

Create an Infisical project and environment. Give a machine identity permission
to read secret values and create/update secrets in the selected folder. Create
that folder first if using a path other than `/`.

```sh
export INFISICAL_PROJECT_ID='<project UUID>'
export INFISICAL_ENVIRONMENT='prod'  # environment slug, not display name
export INFISICAL_SECRET_PATH='/topf'
export INFISICAL_CLIENT_ID='<Universal Auth client ID>'
export INFISICAL_CLIENT_SECRET='<Universal Auth client secret>'
```

Alternatively, set `INFISICAL_TOKEN` to an Infisical **access token** (for example,
a machine identity token). An explicit token takes precedence over Universal
Auth and a rejected token never falls back to other credentials. Legacy service
tokens are not supported.

To use your existing `infisical login`, leave `INFISICAL_TOKEN`,
`INFISICAL_CLIENT_ID`, and `INFISICAL_CLIENT_SECRET` unset. The provider runs
`infisical user get token --plain --silent` for the configured instance and uses
that token for both reads and writes. The CLI must be on `PATH`, with its
keyring accessible and unlocked. Set `INFISICAL_API_URL` when using a non-default
instance, and log into that same instance with `infisical login --domain <URL>`.
The provider defaults to US Cloud; CLI domain settings do not override its URL.
Partial Universal Auth credentials are an error, rather than falling back to
your interactive login. CLI errors and tokens are never printed by the provider.

| Variable | Default | Purpose |
| --- | --- | --- |
| `INFISICAL_API_URL` | `https://app.infisical.com` | Instance base URL, without `/api`; set for your cloud region or self-hosted instance |
| `INFISICAL_PROJECT_ID` | Required | Project UUID |
| `INFISICAL_ENVIRONMENT` | Required | Environment slug |
| `INFISICAL_SECRET_PATH` | `/` | Existing folder path |
| `INFISICAL_TOKEN` | Unset | Explicit access token |
| `INFISICAL_CLIENT_ID` | Unset | Universal Auth client ID |
| `INFISICAL_CLIENT_SECRET` | Unset | Universal Auth client secret |

Use HTTPS for remote instances. TLS verification uses the system trust store.
HTTP is supported for local development. Redirects are rejected; configure the
final instance URL directly. No credentials or bundles are written to disk by
the provider.

## Behavior

```text
topf-infisical secrets get <cluster-name>
topf-infisical secrets put <cluster-name>
```

Each cluster is stored as a shared secret named exactly after the cluster, with
the complete YAML bundle as its value. For example, cluster `production-1` uses
secret `production-1` in project/environment/folder configured above. Cluster
names start with a letter or number and contain only letters, numbers, `.`, `_`
and `-`; case is preserved.

`get` writes the bundle to stdout without modifying it. An explicit Infisical
missing-secret response produces empty stdout and exit status 0, allowing TOPF
to generate its initial bundle. Other failures, including generic HTTP 404s,
missing folders, hidden or empty values, and authentication errors, exit nonzero.
Missing-secret classification deliberately fails closed if the upstream error
format changes.

`put` reads stdin, creates a missing secret or updates an existing one, and
produces no stdout. It preserves multiline content and rejects empty, whitespace-only,
invalid UTF-8 or larger-than-10-MiB bundles. The server may enforce a smaller
limit. Imported secrets and reference expansion are disabled on reads. The
provider transports YAML without parsing or validating its Talos schema.

Requests use the Infisical v4 Secrets API and Universal Auth login API. The
process has a 30-second overall deadline, with a 20-second HTTP timeout.
Error bodies are never printed because they could contain secrets. Errors
include HTTP status codes for diagnosis.

Avoid concurrent initial provisioning of the same cluster. A conflicting create
fails rather than overwriting another newly created bundle. Updates are ordinary
Infisical updates; there is no distributed lock or compare-and-swap.

## Validation

Tests use a local mock HTTP server and cover create/update/read round trips,
exact multiline preservation, authentication precedence, missing secrets,
configuration-related 404s, API failures, malformed/hidden values, input limits,
and redirect rejection. No live Infisical credentials are needed for tests.

## References

- [TOPF provider contract](https://postfinance.github.io/topf/main/providers/)
- [Infisical retrieve API](https://infisical.com/docs/api-reference/endpoints/secrets/read)
- [Infisical create API](https://infisical.com/docs/api-reference/endpoints/secrets/create)
- [Infisical update API](https://infisical.com/docs/api-reference/endpoints/secrets/update)
- [Universal Auth login](https://infisical.com/docs/api-reference/endpoints/universal-auth/login)
