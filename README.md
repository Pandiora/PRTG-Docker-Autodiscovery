# PRTG Docker Container Monitoring (Multi-Platform Probe)

<p align="center">
  <img src="icon.svg" alt="PRTG Docker Monitoring" width="128" height="128"/>
</p>

<p align="center">
  <strong>Monitor Docker containers via PRTG using the Multi-Platform Probe with Script V2 sensors.</strong>
</p>

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [NATS Server Setup](#nats-server-setup)
4. [TLS Certificate Generation](#tls-certificate-generation)
5. [PRTG Configuration](#prtg-configuration)
6. [Probe Container Deployment](#probe-container-deployment)
7. [PRTG Sensor Setup](#prtg-sensor-setup)
8. [Metrics Reference](#metrics-reference)
9. [Troubleshooting](#troubleshooting)
10. [Maintenance](#maintenance)

---

## Overview

This solution provides comprehensive Docker container monitoring through a modified PRTG Multi-Platform Probe container. It uses a two-script architecture for optimal performance:

| Component | Function | Interval |
|-----------|----------|----------|
| **Writer Script** | Collects metrics from ALL containers → writes to shared memory | 60 seconds |
| **Reader Scripts** | One per container, reads from shared memory (~1-2ms each) | 60 seconds |
| **Setup Script** | Creates devices, sensors, configures limits | 1 hour |

---

## Prerequisites

- PRTG Network Monitor (v24.2.96 or later)
- Docker host (Linux) for the probe container
- Windows Server for NATS (recommended: same server as PRTG Core)
- OpenSSL for certificate generation

---

## NATS Server Setup

The Multi-Platform Probe requires a NATS server to communicate with PRTG. This is a **separate component** that must be installed.

### 1. Download NATS Server Installer

Download the NATS Server for Paessler PRTG installer from your PRTG installation:
- Navigate to **Setup → System Administration → Core & Probes → Multi-Platform Probe Connection Settings**
- Download the NATS Server Windows installer

Or download directly from the PRTG installation pack.

### 2. Prepare TLS Certificates

Before installing NATS, you need TLS certificates. See [TLS Certificate Generation](#tls-certificate-generation).

### 3. Install NATS Server

Run the NATS Server installer on your Windows server (recommended: same server as PRTG Core).

During installation, provide:
- **Server Certificate**: `server.crt`
- **Server Key**: `server.key`
- **CA Certificate**: `ca.crt`
- **Port**: `23561` (default)
- **NATS User/Password**: Create credentials for probe authentication

### 4. Verify NATS is Running

Check Windows Task Manager → Services tab → Look for `PRTGNatsServerService`.

For detailed NATS installation instructions, see: [Paessler NATS Installation Guide](https://helpdesk.paessler.com/en/support/solutions/articles/76000064810-step-by-step-installation-guide-for-the-multi-platform-probe#3.-Download-and-install-the-NATS-server)

---

## TLS Certificate Generation

The NATS server requires TLS certificates. You can create self-signed certificates using OpenSSL.

### Quick Self-Signed Certificate Generation (Linux)

```bash
# Create a directory for certificates
mkdir -p certs && cd certs

# 1. Create CA private key and certificate
openssl req -x509 -nodes -newkey rsa:4096 -sha256 \
    -keyout ca.key -out ca.crt -days 3650 \
    -subj "/CN=PRTG-NATS-CA"

# 2. Create server private key and CSR
# Replace "nats.example.com" with your NATS server hostname/IP
openssl req -nodes -newkey rsa:4096 -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=nats.example.com"

# 3. Create SAN (Subject Alternative Names) config file
# Include ALL hostnames/IPs that will connect to NATS
cat > ext.cnf << EOF
subjectAltName=DNS:localhost,DNS:nats.example.com,IP:127.0.0.1,IP:YOUR_NATS_SERVER_IP
EOF

# 4. Sign the server certificate with CA
openssl x509 -req -sha256 -days 3650 \
    -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -extfile ext.cnf

# 5. Verify certificates
openssl x509 -in server.crt -text -noout | grep -A1 "Subject Alternative Name"
```

### Certificate Distribution

| File | Location | Purpose |
|------|----------|---------|
| `ca.crt` | NATS Server, PRTG Core, Probe Container | CA certificate (trust anchor) |
| `server.crt` | NATS Server | Server certificate |
| `server.key` | NATS Server | Server private key (keep secure!) |

**Important**: Copy `ca.crt` to your probe build directory (`./certs/ca.crt`) **BEFORE** building the container.

---

## PRTG Configuration

### 1. Enable Multi-Platform Probe Connections

1. Navigate to **Setup → System Administration → Core & Probes**
2. Scroll to **Multi-Platform Probe Connection Settings**
3. Enable **Allow multi-platform probe connections**
4. Configure:
   - **NATS Server URL**: `tls://YOUR_NATS_SERVER_IP:23561`
   - **NATS User**: (the user created during NATS installation)
   - **NATS Password**: (the password created during NATS installation)
5. Set an **Access Key** (or use the default `multi-platform-probe`)
6. Save and restart PRTG Core when prompted

### 2. Import CA Certificate to PRTG

The CA certificate (`ca.crt`) must be trusted by PRTG:
1. Copy `ca.crt` to the PRTG server
2. Import it into the Windows certificate store (Local Machine → Trusted Root Certification Authorities)

---

## Probe Container Deployment

### 1. Clone the Repository

```bash
git clone https://github.com/Pandiora/PRTG-Docker-Autodiscovery.git
cd PRTG-Docker-Autodiscovery
```

### 2. Add CA Certificate

Copy your CA certificate to the certs directory:

```bash
cp /path/to/ca.crt ./certs/ca.crt
```

### 3. Configure Environment

Copy the example environment file and edit it:

```bash
cp _env .env
nano .env
```

Configure the following values:

```bash
# PRTG API Access
PRTG_HOST=https://your-prtg-server.com
PRTG_USERNAME=prtgadmin
PRTG_PASSWORD=your_prtg_password

# NATS Connection (must use tls://)
MPP_NATS_URL=tls://your-nats-server:23561
MPP_NATS_USER=your_nats_user
MPP_NATS_PASSWORD=your_nats_password

# Probe Access Key (must match PRTG configuration)
MPP_ACCESS_KEY=multi-platform-probe
```

### 4. Build the Container

```bash
docker compose build prtg-probe
```

### 5. Start the Container

```bash
docker compose up -d prtg-probe
```

### 6. Verify Probe Connection

Check the container logs:

```bash
docker logs prtg-probe
```

The probe should connect to NATS and appear in PRTG within 1-2 minutes.

---

## PRTG Sensor Setup

### ⚠️ IMPORTANT: Do NOT Use Auto-Discovery

**Do NOT run network discovery on this probe!** Auto-discovery will create duplicate sensors and break the monitoring setup.

### 1. Accept the Probe

1. Navigate to **Devices → Probes** in PRTG
2. Find the new probe: `multi-platform-probe@<hostname>`
3. The probe should auto-approve, or approve it manually

### 2. Create the Setup Sensor

1. Navigate to the **probe device** (the device directly under the probe, not the probe itself)
2. Click **Add Sensor**
3. Search for **Script V2**
4. Configure:
   - **Name**: `Docker Monitoring Setup`
   - **Script**: `setup_docker_monitoring.py`
   - **Parameters**: (empty, or `--cleanup-orphaned` to auto-delete sensors for stopped containers)
   - **Timeout**: 120 seconds
   - **Interval**: 1 hour (3600 seconds)
5. Create the sensor

### 3. Run the Setup Sensor Manually

After creating the sensor, run it manually once:
1. Right-click the sensor → **Scan Now**
2. Wait for it to complete (this may take 1-2 minutes)

The setup script will automatically:
- Create a **Docker Stats Writer** sensor on the probe device
- Create a **Docker Containers** device under the probe
- Create one sensor per running container
- Configure all channel limits

### 4. Verify Limits are Applied

After the first run, the limits may not be visible immediately. To apply limits right away:
1. Wait for all container sensors to appear
2. Run the setup sensor manually **again**
3. Limits will now be configured on all sensors

### 5. Understanding the Setup Script

| Feature | Description |
|---------|-------------|
| **Auto-discovery** | Finds new containers and creates sensors automatically |
| **Limit Configuration** | Sets warning/error thresholds on all channels |
| **Orphan Detection** | Reports sensors for containers that no longer exist |
| **Orphan Cleanup** | With `--cleanup-orphaned` flag, deletes orphaned sensors |

---

## Metrics Reference

### Container Sensor Channels

| ID | Channel | Limits |
|----|---------|--------|
| 10 | Health Status | Error if < 1 (unhealthy) |
| 11 | CPU Usage | Warning 80%, Error 95% |
| 12 | Memory Usage | (auto-scaled KB/MB/GB) |
| 13 | Memory Usage % | Warning 80%, Error 95% |
| 14 | Network RX Rate | (bytes/sec) |
| 15 | Network TX Rate | (bytes/sec) |
| 16 | Block I/O Read | (auto-scaled) |
| 17 | Block I/O Write | (auto-scaled) |
| 18 | Disk - Container Data | Warning 512MB, Error 1GB |
| 19 | Disk - Container | Warning 1GB, Error 5GB |
| 20 | Disk - Volumes | Warning 1GB, Error 5GB |
| 21 | Disk - Total | Warning 2GB, Error 5GB |
| 22 | Log File Size | Warning 100MB, Error 500MB |
| 23 | Uptime | (seconds) |
| 24 | Restart Count | Warning 1, Error 5 |

### Writer Sensor Channels

| ID | Channel | Limits |
|----|---------|--------|
| 10 | Containers Monitored | - |
| 11 | Collection Time | - |
| 12 | Avg Time per Container | Warning 80ms, Error 100ms |

---

## Troubleshooting

### Probe Not Appearing in PRTG

1. Check container logs: `docker logs prtg-probe`
2. Verify NATS URL uses `tls://` prefix
3. Verify CA certificate is in `./certs/ca.crt` before building
4. Check NATS server is running on Windows
5. Verify access key matches PRTG configuration

### Sensors Showing "No Data"

1. Check Writer sensor is running and healthy
2. Verify shared memory exists:
   ```bash
   docker exec prtg-probe ls /dev/shm/prtg_docker_metrics/
   ```
3. Run writer manually:
   ```bash
   docker exec prtg-probe python3 /opt/paessler/share/scripts/docker_stats_writer.py --verbose
   ```

### First Run Shows Zero Values

On first run, **Network RX/TX Rate** and **CPU %** will show 0. This is normal - they require a previous measurement to calculate the delta. Values will appear correctly on the second run.

### Writer Sensor Failure = Stale Data

If the Writer sensor fails, ALL container sensors will show stale data. The cache expires after 30 minutes. Monitor the Writer sensor health status.

### Debug Mode

Run the writer with debug output:

```bash
docker exec prtg-probe python3 /opt/paessler/share/scripts/docker_stats_writer.py --debug --verbose
```

---

## Maintenance

### Rebuilding After Script Changes

If you modify the Python scripts, you need a **clean rebuild** to ensure changes are applied.

#### Quick Rebuild (scripts only)

Copy updated scripts directly into the running container:

```bash
docker cp docker_stats_writer.py prtg-probe:/opt/paessler/share/scripts/
docker cp setup_docker_monitoring.py prtg-probe:/opt/paessler/share/scripts/
docker exec prtg-probe rm -rf /dev/shm/prtg_docker_metrics/*
```

#### Full Clean Rebuild

When the quick method doesn't work or you've changed the Dockerfile:

```bash
# 1. Stop and remove container
docker compose down

# 2. Remove volumes (contains cached scripts)
docker volume rm $(docker volume ls -q | grep prtg)

# 3. Remove the image
docker rmi $(docker images -q | head -1)

# 4. Rebuild without cache
docker compose build --no-cache prtg-probe

# 5. Start fresh
docker compose up -d prtg-probe
```

#### Nuclear Option (complete reset)

If all else fails:

```bash
docker compose down --volumes --rmi all
docker compose build --no-cache prtg-probe
docker compose up -d prtg-probe
```

**Note**: `--volumes` and `--rmi all` don't take service names, they apply to all services.

### PRTG Cleanup After Rebuild

After a full rebuild, the probe appears as a new device in PRTG:

1. **Delete the old probe device**:
   - Navigate to the old `multi-platform-probe@<hostname>` device
   - Delete it and all its sensors

2. **Unblock the new probe GID** (if connection fails):
   - Navigate to **Setup → System Administration → Core & Probes**
   - Scroll to **Denied GIDs**
   - Remove any blocked entries for your probe
   - Save and wait for the probe to reconnect

3. **Re-run the setup sensor** as described in [PRTG Sensor Setup](#prtg-sensor-setup)

### Backup Considerations

The `/config` volume contains:
- Cached probe ID
- Cached probe device ID
- NATS configuration

Back up this volume if you plan to migrate the probe.

### Updating the Probe Image

```bash
docker compose pull prtg-probe
docker compose up -d --force-recreate prtg-probe
```

---

## Version History

| Component | Version | Changes |
|-----------|---------|---------|
| docker_stats_writer.py | 3.3.1 | Fixed network rate display (integer instead of float) |
| docker_stats_writer.py | 3.3.0 | Network as rate, auto-scaled bytes, removed Memory Limit channel |
| setup_docker_monitoring.py | 12.0.0 | Comprehensive limits, writer sensor limits, updated channel IDs |

---