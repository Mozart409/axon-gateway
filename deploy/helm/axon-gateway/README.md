# axon-gateway Helm chart

Deploys [axon-gateway](../../../README.md) with a Deployment, Service,
ServiceAccount, PodDisruptionBudget, and optionally a Gateway API `HTTPRoute`,
a Prometheus Operator `ServiceMonitor` and `PrometheusRule`, and a Grafana
dashboard ConfigMap. There is no Ingress template.

## Install

```sh
kubectl create secret generic axon-gateway-env \
  --from-literal=AXON_DATABASE_URL='postgres://axon:CHANGE_ME@postgres.example.com/axon'

helm install axon ./rust/axon-gateway/deploy/helm/axon-gateway \
  --set existingSecret=axon-gateway-env \
  --set-file config=my-config.toml
```

`my-config.toml` is a normal axon `config.toml` (see
`rust/axon-gateway/example/config.toml`), with a `[database]` section when you
run more than one replica.

## How it fits together

- **Config.** `config` is the raw `config.toml` text. It lands in a ConfigMap
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
  (mode 0400) and `AXON_KEK_FILE` points at it, which is needed for personal
  backends and catalog credentials.
- **Replicas.** With a database, replicas share sessions, rate limits and
  policy and run singleton jobs once, so no session affinity is needed. The
  default is 2 replicas, `maxUnavailable: 0` rolling updates and a
  PodDisruptionBudget with `minAvailable: 1` (rendered only above 1 replica).
- **Shutdown.** `preStop` sleeps `preStopSleepSeconds` so the pod leaves the
  Service and Gateway before SIGTERM, then the gateway drains SSE streams within
  `terminationGracePeriodSeconds`.
- **Probes.** `/livez` for startup and liveness, `/readyz` for readiness (it
  also checks the database).
- **stdio backends** stay off (`allow_stdio = false`) on Kubernetes.
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
| `replicaCount` | `2` | Replicas; more than 1 needs a `[database]` section |
| `image.repository` | `ghcr.io/mozart409/axon-gateway` | Image |
| `image.tag` | `""` | Defaults to the chart `appVersion` |
| `image.pullPolicy` | `IfNotPresent` | |
| `imagePullSecrets` | `[]` | |
| `nameOverride`, `fullnameOverride` | `""` | |
| `config` | minimal example | The `config.toml` text (required) |
| `existingSecret` | `""` | Secret whose keys become env vars |
| `env`, `envFrom` | `[]` | Extra env / envFrom entries |
| `logLevel` | `info` | `RUST_LOG` |
| `logJson` | `true` | `AXON_LOG_JSON=1` |
| `kek.existingSecret` | `""` | Secret holding the KEK; mounted, `AXON_KEK_FILE` set |
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
