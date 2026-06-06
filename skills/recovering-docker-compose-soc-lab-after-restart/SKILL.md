---
name: recovering-docker-compose-soc-lab-after-restart
description: >-
  Recover a Docker Compose SOC lab after a host reboot or unexpected stop.
  Covers ordered startup for interdependent containers, fixing containers that
  lost their network assignment, nginx upstream errors from stopped containers,
  and the Wazuh manager process recovery sequence.
domain: cybersecurity
subdomain: soc-operations
tags:
- docker
- docker-compose
- soc
- wazuh
- nginx
- operations
- incident-response
- lab-infrastructure
version: '1.0'
author: fortark
license: Apache-2.0
nist_csf:
- PR.IP-04
- RS.MI-01
- RC.RP-01
nist_ai_rmf:
- MANAGE-3.1
---
# Recovering a Docker Compose SOC Lab After Restart

## When to Use

- After a host (Mac Mini, server) reboots unexpectedly or is powered off
- When containers are running but failing to communicate (network connectivity broken)
- When nginx fails to start with "host not found in upstream `<container-name>`"
- When SOAR, TheHive, or Wazuh containers show as running but are unreachable
- When Wazuh processes (analysisd, logcollector) are stopped inside a running container

**Do not** run `docker compose up -d nginx` if nginx has a `depends_on` chain that includes Wazuh — this will restart the Wazuh manager and interrupt all agent connections.

## Prerequisites

- Docker Compose with interdependent services sharing a named network
- Ability to SSH into the host running the SOC stack
- Knowledge of which containers have upstream dependencies in nginx config

## Workflow

### Step 1: Check What Is Actually Running

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | sort
```

Note which containers are stopped or in a restart loop. Compare to your expected container list.

### Step 2: Fix nginx "host not found in upstream" Errors

nginx resolves upstream container names at startup using Docker DNS. If any container listed as an upstream is stopped when nginx starts, nginx will fail entirely — even if only one upstream is unreachable.

```bash
# Find which upstream is failing
docker logs soc-nginx 2>&1 | grep "host not found"
# Output: host not found in upstream "soc-kali-attacker" in /etc/nginx/conf.d/default.conf
```

Fix: start the stopped container **before** reloading or restarting nginx:

```bash
docker start soc-kali-attacker   # or whichever container was missing
docker exec soc-nginx nginx -s reload
```

**Never restart nginx via `docker compose up -d`** if it has `depends_on` pointing to wazuh-dashboard, which in turn depends on wazuh-manager. This cascade-restarts the Wazuh stack.

### Step 3: Recover Containers That Lost Their Network Assignment

Docker Compose containers sometimes fail to get an IP on their named network after a host restart, even though `docker ps` shows them as running. Symptoms:

- Container shows `Up` but is unreachable from other containers
- `docker inspect <container> | grep IPAddress` shows empty or wrong network
- `docker network connect` succeeds but connectivity still fails

When `docker network connect` doesn't fix it, the container's network state is corrupt. The fix is a full remove and recreate:

```bash
# Stop and remove the affected container(s)
docker compose -f docker-compose.yml -f docker-compose.mac.yml stop shuffle-backend shuffle-frontend shuffle-orborus
docker compose -f docker-compose.yml -f docker-compose.mac.yml rm -f shuffle-backend shuffle-frontend shuffle-orborus

# Recreate — Docker Compose re-attaches them to the named network cleanly
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d shuffle-backend shuffle-frontend shuffle-orborus
```

After recreating, reload nginx to pick up new container IPs:

```bash
docker exec soc-nginx nginx -s reload
```

### Step 4: Recover Wazuh Manager Processes

The Wazuh manager container may be running but have all internal processes stopped (analysisd, logcollector, remoted):

```bash
# Check process state inside the container
docker exec soc-wazuh-manager /var/ossec/bin/wazuh-control status

# If processes are stopped:
docker exec soc-wazuh-manager /var/ossec/bin/wazuh-control start
```

If start fails due to a stale lock file:

```bash
docker exec soc-wazuh-manager rm -rf /var/ossec/var/start-script-lock
docker exec soc-wazuh-manager /var/ossec/bin/wazuh-control start
```

### Step 5: Recover Student Lab-Target Containers

Lab-target containers (Ubuntu VMs with Wazuh agents) need their services started manually after any Docker restart — they do not auto-start rsyslogd, Wazuh, or sshd:

```bash
for i in 1 2 3 4 5; do
  docker exec s${i}-lab-target bash -c "rsyslogd; /var/ossec/bin/wazuh-control start; /usr/sbin/sshd"
done
```

Verify agents are connected:

```bash
docker exec soc-wazuh-manager /var/ossec/bin/agent_control -l
# All agents should show as Active
```

### Step 6: Recover Kali Attacker Web Terminal

If the Kali attacker container is running but the web terminal (ttyd) is not:

```bash
docker exec -d soc-kali-attacker ttyd -p 7681 -b /attacker --writable login -f student
```

### Step 7: Recover SOAR Stack

SOAR (Shuffle) has three components that must all be running and network-attached:

```bash
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d shuffle-backend shuffle-frontend shuffle-orborus
```

If Orborus (the workflow runner) is stuck, verify its environment variables are set correctly — particularly:
- `CLEANUP=false` — prevents Orborus from killing backend/frontend
- `SHUFFLE_WORKER_NETWORK=<your-compose-network>` — sets the network for worker containers

### Step 8: Verify Full Stack

```bash
# Check all containers are up
docker ps --format "{{.Names}}: {{.Status}}" | grep -v "Up" | head -20

# Check nginx is serving correctly
curl -sk https://localhost/ | grep -i "title\|error" | head -5

# Check Wazuh agents
docker exec soc-wazuh-manager /var/ossec/bin/agent_control -l | grep -v "Disconnected"

# Check OpenSearch health
docker exec soc-opensearch curl -sk -u admin:admin https://localhost:9200/_cluster/health | python3 -m json.tool
```

## Recommended Startup Order

When bringing up a full SOC stack from scratch:

1. OpenSearch (all persistent storage backends)
2. Wazuh manager, Wazuh dashboard
3. TheHive, Cortex, MISP (case management + enrichment)
4. Shuffle backend, frontend, Orborus (SOAR)
5. Suricata (network IDS)
6. Kali attacker container
7. Nginx (last — depends on all upstream containers)

```bash
# Phased startup example
docker compose up -d soc-opensearch soc-cortex-opensearch
sleep 30
docker compose up -d soc-wazuh-manager soc-wazuh-dashboard
sleep 20
docker compose up -d soc-thehive soc-cortex soc-misp
docker compose up -d shuffle-backend shuffle-frontend shuffle-orborus
docker compose up -d soc-suricata soc-kali-attacker
docker compose up -d soc-nginx
```

## Key Concepts

| Term | Definition |
|------|------------|
| **nginx upstream resolution** | nginx resolves upstream container names at startup via Docker DNS; any stopped upstream causes nginx to refuse to start entirely |
| **Network assignment corruption** | Docker Compose containers can show as running but have no IP on their configured network after a host restart; `docker network connect` does not fix this — a full rm + recreate is required |
| **Wazuh process vs container state** | The Wazuh manager container can be running while all Wazuh processes inside (analysisd, logcollector, remoted) are stopped; always check with `wazuh-control status` |
| **CLEANUP=false** | Shuffle Orborus environment variable that prevents it from garbage-collecting the backend and frontend containers it considers to be worker containers |
| **depends_on cascade** | docker compose respects `depends_on` when running `up -d <service>` — starting nginx via compose will also start its dependencies, including Wazuh, even if you only wanted nginx |

## Tools & Systems

- **Docker Compose**: Orchestrates multi-container SOC stack; `depends_on` chains cause cascading restarts
- **Wazuh Manager**: SIEM; internal processes stop independently of the container
- **Shuffle Orborus**: SOAR workflow runner; must be on the same Docker network as worker containers it spawns
- **nginx**: Reverse proxy; resolves all upstreams at startup — all must be running before nginx loads
