# Troubleshooting

Symptom, likely cause, fix. Source: the README of the running version and the
other references. Read the gateway log first; startup errors name the variable.

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Login returns to the login page forever | `AXON_BASE_URL` is plain `http://` on a non-`localhost` host (the `__Host-` cookies are always `Secure` and get dropped), or it differs from the URL in the browser | Serve over HTTPS and set `AXON_BASE_URL` to the exact public URL. Do not loosen the proxy or add CORS headers |
| IdP says `redirect_uri` mismatch | The registered redirect URI differs from the one the gateway sends | Copy the value from "Values for your identity provider" on `/ui/admin/config/oidc-providers`, or register `{base_url}/auth/callback` exactly (no trailing slash, same scheme and host as `AXON_BASE_URL`) |
| Logged in but no `admin` badge, Admin pages missing | The groups claim is not sent (Pocket ID without the `groups` scope; Entra sends object ids, not names; overage past ~200 groups), or `AXON_OIDC_ADMIN_GROUPS` does not match the claim value | Add the scope or claim, use `graph_overage` or SCIM for overage, match the value exactly, then log in again (admin is decided at login) |
| Admin sees "No grant yet" on "My tools", tools missing | No grant: `admin` holds every permission but still needs a grant per backend | Follow "Add a grant" (`/ui/admin#grants`) and grant `authenticated` or the user's group |
| Users page flags "duplicate" or "issuer not configured" | The issuer string changed spelling (`localhost` vs `127.0.0.1`, trailing slash); users are unique on `(issuer, subject)` | Switch back to the original issuer string; the old rows then match again |
| Gateway refuses to start | No KEK (`AXON_KEK_FILE`/`AXON_KEK`), a KEK secret shorter than 32 characters, a config file or `AXON_GATEWAY_CONFIG` given in database mode, `AXON_OIDC_CLIENT_ID` missing while `AXON_OIDC_ISSUER` is set, or an empty client secret file | Read the error; fix the variable (`pwgen -s 48 1` for the KEK), import the file with `admin import-config` and start without it |
| stdio backend cannot be saved (400) | `AXON_ALLOW_STDIO` is not set | Set `AXON_ALLOW_STDIO=true` and restart |
| Hostname backends fail with name-resolution errors in the container | The container fixes `/etc/resolv.conf` at start | Pin `dns:` (Compose) or `--dns=<ip>`, or restart after host DNS changes |
| Secret file not readable in the container | The container runs as UID 65532 | Make mounted secrets readable by that UID |
| Changed `[personal_backends]` settings or `AXON_*` env, nothing happens | These are read at startup only | Restart; every other config change applies within seconds on every replica |
| Warning "secret that cannot be unsealed" after KEK rotation | The old KEK line was dropped before `admin rewrap-secrets` | Restore the old line below the new one, run `admin rewrap-secrets`, then drop it |
| Editing a backend URL or transport is refused | Changing where it connects requires its stored secrets re-entered or cleared | Re-enter or clear the secrets in the same request (`""` clears) |
| Locked out, no working provider | The IdP is misconfigured or gone | `axon-gateway admin login-link` with the same environment, open it within 15 minutes, fix the provider, then disable "Break-glass admin" on `/ui/admin/users` |
| `/readyz` answers 503 | The database did not answer within 2 s | Check `AXON_DATABASE_URL`, the database and the network |
| 403 on a dashboard action, CSP or "cross-site" errors | A proxy rewrites `Origin`/`Host`, serves the gateway under a path prefix or forwards plain HTTP, or `AXON_BASE_URL` is not the browser's URL | Serve at the root of its own HTTPS host, pass the original host, set `AXON_BASE_URL` to the public URL; do not loosen the proxy |
| Client connects but lists no tools | No grant for the user's groups, or the backend is down | Check "My tools", the grant, and the backend card on the Overview |
| Overview still shows "Set up the gateway" | A checklist item is open (provider, admin group, backend, grant, client) | Finish the open item; the card names it |
