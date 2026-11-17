# ct49-egress (temporary, task #49)

Owned by `ezebright898`. Purpose: use a **GitHub-hosted runner (Azure egress)** as an
independent network vantage point for a one-shot, read-only TCP/HTTP truth mapping of four
in-scope cardtonic hosts:

- 129.212.142.60
- 129.212.194.148
- 142.93.160.150
- 64.227.117.180

Why: the main worker's egress only really passes 80/443 to some of these hosts (SYN gets
"fake-accepted" by a middlebox), so the asset inventory's `open_ports` were unverified.
The runner does a real `socket.create_connection()` per port, grabs banners, and runs
read-only follow-up probes (`GET /version`, `/healthz`, kubelet `/pods`, Docker
`/containers/json`, WebHDFS `LISTSTATUS`, Redis `PING/INFO`, Mongo `isMaster`, ssh-keyscan
+ auth-method enumeration, Traefik vhost classification).

Nothing is written to the targets: TCP handshake, GET/HEAD, ssh-keyscan only.

Rollback: this repo is disposable — archive or delete it after the task.
