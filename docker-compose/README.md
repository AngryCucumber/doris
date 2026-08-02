# MassDB SQL ARM64 Image Deployment

The image contains the complete root-build output, but these Compose files run
only FE and BE. From the repository root, load the image archive on every
target server, then enter this directory before starting services:

```bash
docker load -i output/massdb-sql-2.0.5-arm64.tar
cd docker-compose
```

## Mounted configuration

Edit `conf/fe/fe.conf` and `conf/be/be.conf` on the host. Compose mounts these
directories read-only; the entrypoint copies their contents into the container
before startup, so certificates or other configuration files can also be added
there. Apply changes with `docker compose ... restart`.

`PRIORITY_NETWORKS` has the highest priority. If it is unset, an active
`priority_networks` value in the mounted configuration is preserved; otherwise
the entrypoint derives a `/24` network from `FE_IP` or `BE_IP`.

## Same server

Use profiles to control the services independently:

```bash
# FE only
docker compose -f docker-compose.same-host.yml --profile fe up -d
# BE only (start after FE is available)
docker compose -f docker-compose.same-host.yml --profile be up -d
# FE and BE together
docker compose -f docker-compose.same-host.yml --profile all up -d
```

## Different servers

The cross-server files use host networking so FE and BE advertise routable host
addresses. On the FE server:

```bash
FE_IP=10.0.0.10 docker compose -f docker-compose.fe-host.yml up -d
```

On the BE server:

```bash
FE_HOST=10.0.0.10 BE_IP=10.0.0.11 \
  docker compose -f docker-compose.be-host.yml up -d
```

Allow FE ports `8030`, `8070`, `9010`, `9020`, and `9030`, and BE ports `8040`,
`8050`, `8060`, `9050`, and `9060` through host firewalls. If the advertised
address is not IPv4 or the network is not `/24`, set `PRIORITY_NETWORKS`
explicitly (for example, `10.0.0.0/16`). Set `DATA_ROOT` to choose persistent
storage paths for cross-server deployment.
