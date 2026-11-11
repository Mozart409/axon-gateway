# axon-gateway Helm chart

Deploys [axon-gateway](../../../README.md) with a Deployment, Service,
ServiceAccount, PodDisruptionBudget, optionally a one-shot config import Job,
and optionally a Gateway API `HTTPRoute`,
a Prometheus Operator `ServiceMonitor` and `PrometheusRule`, and a Grafana
dashboard ConfigMap. There is no Ingress template.

## Install

The chart runs in one of two modes (see the gateway README, "Database mode").

**Database mode** (`database.enabled=true`) is the one for several replicas and
for users and RBAC. The gateway reads no config file: the database URL, the
KEK, the public URL and an optional bootstrap OIDC provider are environment,
and backends, toolsets, providers and settings are managed in the dashboard.

```sh
kubectl create secret generic axon-gateway-db \
  --from-literal=url='postgres://axon:CHANGE_ME@postgres.example.com/axon'
kubectl create secret generic axon-gateway-kek \
  --from-literal=kek="$(pwgen -s 48 1)"

helm install axon ./rust/axon-gateway/deploy/helm/axon-gateway \
  --set database.enabled=true \
  --set database.existingSecret=axon-gateway-db \
  --set kek.existingSecret=axon-gateway-kek \
  --set baseUrl=https://axon.example.com \
  --set oidc.issuer=https://id.example.com \
  --set oidc.clientId=axon \
  --set 'oidc.adminGroups={axon-admins}'
```

Without `oidc.issuer` there is no provider yet: log in with
`kubectl exec deploy/<release>-axon-gateway -- axon-gateway admin login-link`
and add one in the dashboard.

**Standalone mode** (the default) is one gateway with a TOML file, no users and
no RBAC; the file may not carry `[database]`, `[[auth.oidc]]`, `[rbac]` or
per-user backends.

```sh
helm install axon ./rust/axon-gateway/deploy/helm/axon-gateway \
  --set existingSecret=axon-gateway-env \
  --set-file config=my-config.toml
```

`my-config.toml` is a normal axon `config.toml` (see
`rust/axon-gateway/example/config.toml`).

## Importing a config file

To move an existing `config.toml` into the database, install or upgrade in
database mode with the file as `import.config` and `import.enabled=true`:

```sh
helm upgrade axon ./rust/axon-gateway/deploy/helm/axon-gateway -f values.yaml \
  --set import.enabled=true --set-file import.config=old-config.toml
kubectl logs job/<release>-axon-gateway-import
```

A `pre-install,pre-upgrade` hook Job (with a hook ConfigMap holding the file)
runs `axon-gateway admin import-config /config/config.toml` with the database
URL and the KEK. Things to know:

- It is **off by default** and meant to run once. The file wins, so every
  install or upgrade with it on overwrites what was changed in the dashboard
  since. Turn it off after the first run.
- `import.dryRun=true` only reports what would change.
- A `[[tokens]]` entry becomes a service account with a new token. The tokens
  are printed to the Job's log **once** (`name`, a tab, the token; the summary
  and warnings are on the same log's stderr). Read them there. The Job is
  deleted a day after it finishes, and an existing account never gets a second
  token. They expire after 365 days.
- `${VAR}` references in the file resolve from `existingSecret`, `env` and
  `envFrom`, which the Job gets too.
- Keys that are environment-only in database mode (`bind`, `base_url`,
  `auth_token`, `allow_stdio`, `[database]`) are warned about and not imported;
  use `baseUrl`, `bind` and `allowStdio` here.

## How it fits together

- **Database mode.** With `database.enabled` the Deployment gets
  `AXON_DATABASE_URL` (from `database.existingSecret`/`database.key`),
  `AXON_BASE_URL`, `AXON_BIND`, `AXON_ALLOW_STDIO` and the optional
  `AXON_OIDC_*` bootstrap provider (the client secret is mounted from
  `oidc.clientSecret.existingSecret` as a file). `kek.existingSecret` is
  required. No config ConfigMap is created or mounted and `config` is ignored.
  Changes made in the dashboard reach every replica within seconds, so there is
  nothing to roll.
- **Config (standalone).** `config` is the raw `config.toml` text. It lands in a ConfigMap
  mounted read-only as a directory at `/etc/axon`, and `AXON_GATEWAY_CONFIG`
  points at `/etc/axon/config.toml`. The gateway watches the file and
  hot-reloads it, and it handles the kubelet's `..data` symlink swap. So there
  is deliberately **no checksum annotation** on the config: editing `config`
  does not restart the pods. The kubelet can take up to a minute to refresh the
  mounted file. `${VAR}` references in the TOML are resolved from the
  environment when the file loads.
- **Secrets** are read from the environment at start. `existingSecret` is
  attached with `envFrom` (every key becomes a variable: the database URL, OIDC
  client secrets, backend tokens). After changing a Secret, run
  `kubectl rollout restart deploy/<release>-axon-gateway`.
- **KEK.** Set `kek.existingSecret` and `kek.key`; the key is mounted as a file
  (mode 0400) and `AXON_KEK_FILE` points at it. Database mode requires it (it
  seals the secrets of backends, providers and personal servers); a standalone
  gateway has no use for it.
- **Replicas.** With a database, replicas share sessions, rate limits and
  policy and run singleton jobs once, so no session affinity is needed. The
  default is 2 replicas, `maxUnavailable: 0` rolling updates and a
  PodDisruptionBudget with `minAvailable: 1` (rendered only above 1 replica).
- **Shutdown.** `preStop` sleeps `preStopSleepSeconds` so the pod leaves the
  Service and Gateway before SIGTERM, then the gateway drains SSE streams within
  `terminationGracePeriodSeconds`.
- **Probes.** `/livez` for startup and liveness, `/readyz` for readiness (it
  also checks the database).
- **stdio backends** stay off on Kubernetes (`allowStdio: false`, or
  `allow_stdio = false` in a standalone file). Only `allowStdio` lets the
  dashboard save a stdio backend.
- **Tracing.** Set the standard `OTEL_*` variables through `env`.
- **Metrics.** `/metrics` on the service port; enable `serviceMonitor`.

## Observability

`files/grafana-dashboard.json` and `files/prometheus-rules.yaml` are copies of
`rust/axon-gateway/example/observability/`, which is the source (Helm cannot
read outside the chart). After editing the source, copy it over; `just
axon-deploy-check` fails when they differ. The PrometheusRule renders the same
rules, with `job="axon-gateway"` rewritten to `prometheusRule.job` (default: the
Service name, which is the job a ServiceMonitor produces).

The dashboard has a `DS_PROMETHEUS` data source variable plus `job` and
`instance` variables.

## Values

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `2` | Replicas; more than 1 needs `database.enabled` |
| `image.repository` | `ghcr.io/mozart409/axon-gateway` | Image |
| `image.tag` | `""` | Defaults to the chart `appVersion` |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride`, `fullnameOverride` | `""` | |
| `database.enabled` | `false` | Database mode: configuration in Postgres, no config file |
| `database.existingSecret`, `database.key` | `""`, `url` | Secret and key holding the Postgres URL (`AXON_DATABASE_URL`); required in database mode |
| `baseUrl` | `""` | `AXON_BASE_URL`; required in database mode |
| `bind` | `0.0.0.0:8080` | `AXON_BIND` |
| `allowStdio` | `false` | `AXON_ALLOW_STDIO` |
| `oidc.issuer`, `oidc.clientId` | `""` | Bootstrap OIDC provider (`AXON_OIDC_ISSUER`, `AXON_OIDC_CLIENT_ID`); database mode |
| `oidc.id`, `oidc.displayName`, `oidc.adminGroups` | `""`, `""`, `[]` | `AXON_OIDC_ID` (default `sso`), `AXON_OIDC_DISPLAY_NAME`, `AXON_OIDC_ADMIN_GROUPS` |
| `oidc.clientSecret.existingSecret`, `.key` | `""`, `client-secret` | Secret mounted as a file for `AXON_OIDC_CLIENT_SECRET_FILE` |
| `import.enabled` | `false` | Hook Job running `admin import-config` on `import.config` (database mode) |
| `import.dryRun` | `false` | Report only |
| `import.config` | `""` | The `config.toml` text to import; required with `import.enabled` |
| `config` | minimal example | Standalone: the `config.toml` text (ignored in database mode) |
| `existingSecret` | `""` | Secret whose keys become env vars |
| `env`, `envFrom` | `[]` | Extra env / envFrom entries |
| `logLevel` | `info` | `RUST_LOG` |
| `logJson` | `true` | `AXON_LOG_JSON=1` |
| `kek.existingSecret` | `""` | Secret holding the KEK; mounted, `AXON_KEK_FILE` set; required in database mode |
| `kek.key` | `kek` | Key in that Secret |
| `serviceAccount.create` | `true` | |
| `serviceAccount.name` | `""` | |
| `serviceAccount.annotations` | `{}` | |
| `podAnnotations`, `podLabels` | `{}` | |
| `podSecurityContext` | non-root 65532, RuntimeDefault seccomp | |
| `securityContext` | read-only rootfs, no privilege escalation, drop ALL | |
| `resources` | 100m / 128Mi requests, 512Mi memory limit | |
| `preStopSleepSeconds` | `10` | Sleep before SIGTERM |
| `terminationGracePeriodSeconds` | `60` | |
| `service.type` | `ClusterIP` | |
| `service.port` | `8080` | |
| `service.annotations` | `{}` | |
| `podDisruptionBudget.enabled` | `true` | Rendered only when `replicaCount > 1` |
| `podDisruptionBudget.minAvailable` | `1` | |
| `httpRoute.enabled` | `false` | Gateway API HTTPRoute |
| `httpRoute.parentRefs` | `[]` | Required when enabled |
| `httpRoute.hostnames` | `[]` | |
| `httpRoute.path` | `/` | PathPrefix |
| `httpRoute.timeouts` | `{}` | HTTPRoute rule timeouts |
| `httpRoute.annotations` | `{}` | |
| `serviceMonitor.enabled` | `false` | Needs the Prometheus Operator CRDs |
| `serviceMonitor.namespace`, `.labels` | `""`, `{}` | |
| `serviceMonitor.interval`, `.scrapeTimeout` | `30s`, `10s` | |
| `prometheusRule.enabled` | `false` | |
| `prometheusRule.namespace`, `.labels` | `""`, `{}` | |
| `prometheusRule.job` | `""` | Job in `AxonGatewayDown`; default is the Service name |
| `grafanaDashboard.enabled` | `false` | ConfigMap with `grafana_dashboard: "1"` |
| `grafanaDashboard.namespace` | `""` | |
| `grafanaDashboard.folder` | `""` | `grafana_folder` annotation |
| `nodeSelector`, `tolerations`, `affinity`, `topologySpreadConstraints` | empty | Scheduling passthrough |

## Validate

From the repo root: `just axon-deploy-check` (helm lint and template with
default and `ci/all-on-values.yaml`, kubeconform, promtool, jq, copy check).
