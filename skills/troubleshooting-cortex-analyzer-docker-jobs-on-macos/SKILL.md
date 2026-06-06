---
name: troubleshooting-cortex-analyzer-docker-jobs-on-macos
description: >-
  Fix Cortex analyser failures on macOS Docker Desktop caused by Docker-in-Docker
  job directory path mismatch. Covers the "mounts denied" error, why named volumes
  fail, the identical bind-mount path fix, and the TheHive 5 / Cortex 3 report
  panel incompatibility workaround.
domain: cybersecurity
subdomain: soc-operations
tags:
- cortex
- thehive
- docker
- macos
- soar
- analyzers
- docker-in-docker
- incident-response
version: '1.0'
author: fortark
license: Apache-2.0
nist_csf:
- DE.AE-02
- RS.AN-01
- RS.AN-03
nist_ai_rmf:
- MEASURE-2.7
- MANAGE-3.1
---
# Troubleshooting Cortex Analyser Docker Jobs on macOS

## When to Use

- When Cortex analysers (AbuseIPDB, VirusTotal, Shodan, etc.) fail immediately after being triggered
- When Cortex logs show `mounts denied` or `cannot bind mount path … to container`
- When analysers worked in a Linux Docker environment but fail after moving to macOS Docker Desktop
- When TheHive shows a Cortex job as "Success" but the report panel in the case UI is empty
- When the report panel opens but displays nothing (no taxonomies, no artifacts)

## Prerequisites

- Cortex 3.x running in Docker on macOS Docker Desktop
- Cortex configured to run analyser containers via Docker-in-Docker (`/var/run/docker.sock` mounted)
- Docker Desktop for macOS — the Docker VM layer is what causes the path mismatch

## Root Cause: Why Named Volumes Break Docker-in-Docker on macOS

When Cortex runs an analyser, it launches a short-lived Docker container (the analyser worker). Cortex passes a job directory as a bind mount into this worker container. The worker reads input from and writes output to that directory.

On macOS, Docker runs inside a Linux VM (HyperKit or VZ). Named Docker volumes live inside this VM at an internal path — they are **not** accessible as host paths from macOS. When Cortex is configured to use a named volume (`cortex-data:/opt/cortex/jobs`), the path it passes to the analyser container is `/opt/cortex/jobs` — a path that exists inside the Cortex container but does not exist on the macOS host filesystem.

Docker Desktop's bind-mount sharing only works for **macOS host paths** (under `/Users`, `/tmp`, etc.). So when Cortex tells Docker to bind-mount a path that is actually inside the Docker VM, Docker Desktop rejects it:

```
Error response from daemon: Mounts denied:
The path /opt/cortex/jobs is not shared from the host and is not known to Docker.
```

## Workflow

### Step 1: Diagnose the Error

Check Cortex container logs immediately after triggering an analyser:

```bash
docker logs soc-cortex 2>&1 | grep -i "error\|denied\|mount\|job" | tail -20
```

Look for:
```
Mounts denied: The path /opt/cortex/jobs is not shared ...
```
or
```
cannot bind mount ... path does not exist on host
```

Also check if the named volume is the configured job directory:

```bash
grep -i "job.directory" ~/soc-platform/cortex/config/application.conf
# If it shows /opt/cortex/jobs → that's the problem path
```

### Step 2: Create the Job Directory on the macOS Host

The fix is to use a real macOS host path for jobs instead of a Docker volume:

```bash
mkdir -p /Users/<yourusername>/soc-platform/cortex/jobs
```

The path must be under `/Users` (or another Docker Desktop shared directory) so Docker Desktop allows bind mounts to it.

### Step 3: Update application.conf

Change `job.directory` to the macOS host path:

```
# cortex/config/application.conf
job.directory = "/Users/<yourusername>/soc-platform/cortex/jobs"
```

**Critical:** The path here must be **identical** to the bind mount path in docker-compose. If they differ, Cortex passes one path to Docker and Docker looks for a different path.

### Step 4: Update docker-compose to Use an Identical Bind Mount

In `docker-compose.yml` (or `docker-compose.mac.yml` if using an override file), replace the named volume with an identical host:container bind mount:

```yaml
# Before (broken on macOS):
services:
  cortex:
    volumes:
      - cortex-data:/opt/cortex/jobs

volumes:
  cortex-data:
```

```yaml
# After (works on macOS Docker Desktop):
services:
  cortex:
    volumes:
      # Host path and container path are identical — Docker-in-Docker can bind-mount it
      - /Users/<yourusername>/soc-platform/cortex/jobs:/Users/<yourusername>/soc-platform/cortex/jobs
      - /var/run/docker.sock:/var/run/docker.sock
      - ./cortex/config/application.conf:/etc/cortex/application.conf:ro
      - ./cortex/analyzers-config:/opt/cortex/analyzers-config:ro
```

The host path and container path being **identical** is the key. When Cortex reads `job.directory` from `application.conf` and passes it to Docker as a bind mount source, Docker Desktop sees a real macOS host path and allows it.

### Step 5: Remove the Named Volume and Recreate Cortex

```bash
# If cortex-data volume still exists in docker-compose.yml, remove it from the volumes section too
# Then recreate the cortex container:
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d --force-recreate cortex
```

If `cortex-data` was previously used, Docker Compose may error that it is still referenced elsewhere. Remove all references from both compose files before recreating.

### Step 6: Verify Analysers Work

1. In Cortex UI, navigate to an organisation → Analysers → enable one (e.g., AbuseIPDB_2_0)
2. Trigger a run: from TheHive, add an observable (IP address), click "Run Analysers"
3. In Cortex job list, the status should move from "Waiting" → "Running" → "Success"
4. Check the jobs directory is being populated:
   ```bash
   ls /Users/<yourusername>/soc-platform/cortex/jobs/
   # Should show directories named by job ID
   ```

---

## TheHive 5 + Cortex 3: Report Panel Shows Empty (Known Bug)

Even after analysers complete successfully, the TheHive case observable report panel may display as empty. This is a known incompatibility between TheHive 5.3.x and Cortex 3.1.x.

**Root cause:** Cortex 3.x returns a `summary` field (containing taxonomies — the coloured tags shown in TheHive) in the job report. TheHive 5.3.4 drops this field when storing the report in its database (`extraData`). When the report panel opens, it reads from `extraData`, which no longer has the `summary` field, so the panel renders empty.

**Workaround:** Do not use the TheHive case report panel for IOC enrichment. Instead, access Cortex results through a tool that reads from the Cortex API directly (not from TheHive's stored extraData):

```
# SOC Tools dashboard → IOC Lookup tab
# Enter the observable → select analyser → run → view results
# This calls the Cortex /api/job/<id>/report endpoint directly
```

If you run the analysis from TheHive (for logging purposes) and need to see results, check the Cortex job list at `http://<cortex-host>:9001` → Jobs → click the job → Report.

**Permanent fix:** Upgrade to TheHive 5.4+ or Cortex 3.2+ when releases address this incompatibility. Until then, treat the TheHive report panel as non-functional for taxonomy display.

---

## Key Concepts

| Term | Definition |
|------|------------|
| **Docker-in-Docker** | Pattern where a containerised process (Cortex) launches child containers (analyser workers) via the host Docker socket; requires careful path alignment |
| **Named volume vs bind mount** | Named volumes live inside the Docker VM on macOS — not on the macOS host filesystem. Bind mounts with absolute macOS host paths are accessible to Docker Desktop |
| **Identical path bind mount** | Mounting a host path to the same path inside the container (e.g., `/Users/x/jobs:/Users/x/jobs`); required for Docker-in-Docker when the inner container must reference the same path |
| **job.directory** | Cortex `application.conf` setting for where analyser job input/output is staged; must be a macOS host path when running on macOS Docker Desktop |
| **extraData (TheHive)** | TheHive's stored copy of Cortex report data; in 5.3.x, the `summary` / taxonomies field is dropped on storage, causing an empty report panel |

## Tools & Systems

- **Cortex 3.1.x**: IOC enrichment platform; runs analysers as Docker containers
- **TheHive 5.3.x**: Case management; integrates with Cortex for observable enrichment; has bug where taxonomy summary is dropped
- **Docker Desktop for macOS**: Runs Docker inside a Linux VM; only macOS host paths under `/Users` (and `/tmp`, `/Volumes`) are shareable as bind mounts

## Common Scenarios

### Scenario: Cortex Analyser Stuck on "Waiting" or Fails Immediately

**Symptom**: Job appears in Cortex with status "Waiting" and never progresses, or immediately transitions to "Failure".

**Diagnosis**:
```bash
docker logs soc-cortex 2>&1 | grep -i "error\|denied\|exception" | tail -30
```

**Most common cause on macOS**: Named volume path not accessible on host. Fix: switch to identical bind mount path + update `application.conf`.

### Scenario: Analysers Work but Report Always Empty in TheHive

**Symptom**: Cortex job shows "Success", clicking the report icon in TheHive opens a side panel that is completely blank.

**Diagnosis**:
```bash
# Call Cortex report API directly to confirm data exists:
curl -s -H "Authorization: Bearer <cortex-api-key>" \
  http://<cortex-host>:9001/api/job/<job-id>/report | python3 -m json.tool | head -30
# If this returns data → the bug is in TheHive's storage layer, not Cortex
```

**Workaround**: Redirect analysts to SOC Tools IOC Lookup or direct Cortex job view. Do not block workflows on TheHive report panel display.
