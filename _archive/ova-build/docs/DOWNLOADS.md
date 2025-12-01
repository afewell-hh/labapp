# Hedgehog Lab Appliance - Downloads

This guide provides download links, verification procedures, and troubleshooting for Hedgehog Lab Appliance builds.

## Table of Contents

- [Available Downloads](#available-downloads)
- [Download Methods](#download-methods)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Download Size Comparison](#download-size-comparison)
- [System Requirements](#system-requirements)

## Available Downloads

### Standard Build (Recommended for Self-Paced Learning)

**Size:** 15-20 GB compressed
**First Boot Time:** 15-20 minutes (one-time initialization)
**Use Case:** Individual learning, development, testing

The standard build downloads container images and initializes the lab environment during first boot. This provides a smaller download size but requires a longer initial setup time.

**Latest Release:**
```
https://github.com/afewell-hh/labapp/releases/latest/download/hedgehog-lab-standard-latest.ova
```

**Specific Versions:**
```
v0.1.0: https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
```

**Checksums:**
```
v0.1.0: https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova.sha256
```

### Pre-warmed Build (For Workshops and Training Events)

**Size:** 80-100 GB compressed
**First Boot Time:** 2-3 minutes
**Use Case:** Workshops, training events, demos with many participants

Pre-warmed builds include all container images pre-pulled and the lab environment pre-initialized. This provides the fastest first-boot experience but requires significantly more storage and download time.

**Storage Location:** AWS S3
**Download URLs:**

```
Base URL: https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/

Version Pattern:
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v{VERSION}/hedgehog-lab-prewarmed-{VERSION}.ova

Example (v0.2.0):
OVA:      https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
Checksum: https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova.sha256
Metadata: https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.metadata.json
```

**Event-Specific Builds:**

For specific workshops or conferences, event-optimized builds may be available:
```
https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/prewarmed/events/{EVENT-NAME}/hedgehog-lab-{EVENT-NAME}.ova
```

> **Note:** Event-specific builds are typically distributed via USB drives or local network storage at the event due to their large size.

## Download Methods

### Browser Download (Simple)

**Standard Build:**
1. Navigate to [Releases Page](https://github.com/afewell-hh/labapp/releases)
2. Find the desired version
3. Click on the `.ova` file to download
4. Download the corresponding `.sha256` checksum file

**Limitations:**
- May not support resume for interrupted downloads
- Browser memory limits may affect very large files (80-100 GB)
- Slower for large pre-warmed builds

### Command-Line Download (Recommended)

**Using wget (Linux/macOS/Windows with WSL):**

```bash
# Standard build
wget https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
wget https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova.sha256

# Pre-warmed build (when available)
wget https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
wget https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova.sha256
```

**Using curl (macOS/Linux):**

```bash
# Standard build
curl -LO https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
curl -LO https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova.sha256

# Pre-warmed build
curl -LO https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
curl -LO https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova.sha256
```

**Benefits:**
- Resume interrupted downloads with `-c` flag
- Better progress tracking
- Scriptable for automation
- Works reliably with large files

### Advanced Download Methods

**Using aria2c (Fastest for Large Files):**

aria2c supports multi-connection downloads and automatic retry, making it ideal for very large files.

```bash
# Install aria2c
# Ubuntu/Debian: sudo apt install aria2
# macOS: brew install aria2
# Windows: Download from https://aria2.github.io/

# Download with 16 parallel connections
aria2c -x 16 -s 16 https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova

# Resume interrupted download
aria2c -c -x 16 -s 16 https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
```

**Benefits:**
- 2-5x faster than wget/curl for large files
- Automatic resume on connection failure
- Multiple connections to maximize bandwidth
- Progress reporting with ETA

**Using AWS CLI (For S3-hosted pre-warmed builds):**

```bash
# Install AWS CLI (no credentials needed for public downloads)
pip install awscli

# Download from S3
aws s3 cp s3://hedgehog-lab-artifacts/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova . --no-sign-request
aws s3 cp s3://hedgehog-lab-artifacts/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova.sha256 . --no-sign-request
```

## Verification

**Always verify the integrity of downloaded files before importing them into your hypervisor.**

### SHA256 Checksum Verification

**Linux/macOS:**
```bash
# Verify checksum
sha256sum -c hedgehog-lab-standard-0.1.0.ova.sha256

# Expected output:
hedgehog-lab-standard-0.1.0.ova: OK
```

**Windows (PowerShell):**
```powershell
# Get file hash
$hash = Get-FileHash -Algorithm SHA256 hedgehog-lab-standard-0.1.0.ova

# Compare with checksum file
$expectedHash = (Get-Content hedgehog-lab-standard-0.1.0.ova.sha256).Split(' ')[0]

if ($hash.Hash -eq $expectedHash.ToUpper()) {
    Write-Host "Checksum verification: OK" -ForegroundColor Green
} else {
    Write-Host "Checksum verification: FAILED" -ForegroundColor Red
}
```

### Manual Checksum Comparison

If you prefer manual verification:

1. **Calculate checksum of downloaded file:**
   ```bash
   # Linux/macOS
   sha256sum hedgehog-lab-standard-0.1.0.ova

   # Windows PowerShell
   Get-FileHash -Algorithm SHA256 hedgehog-lab-standard-0.1.0.ova
   ```

2. **View expected checksum:**
   ```bash
   cat hedgehog-lab-standard-0.1.0.ova.sha256
   ```

3. **Compare manually:** The checksums should match exactly.

### File Size Verification

Check that the downloaded file size matches the expected size:

```bash
# Linux/macOS
ls -lh hedgehog-lab-standard-0.1.0.ova

# Windows PowerShell
Get-Item hedgehog-lab-standard-0.1.0.ova | Select-Object Name, Length
```

**Expected Sizes:**
- Standard build: 15-20 GB
- Pre-warmed build: 80-100 GB

If the file size is significantly different, the download may be incomplete or corrupted.

## Troubleshooting

### Download Interrupted or Corrupted

**Problem:** Download stops mid-transfer or checksum verification fails

**Solutions:**

1. **Resume with wget:**
   ```bash
   wget -c https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
   ```

2. **Resume with curl:**
   ```bash
   curl -C - -LO https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
   ```

3. **Use aria2c with automatic retry:**
   ```bash
   aria2c -x 16 -s 16 --retry-wait=5 --max-tries=10 https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
   ```

4. **Check disk space:**
   ```bash
   df -h .
   ```
   Ensure you have at least 2x the file size available (for download + extraction).

5. **Verify network stability:**
   - Test connection to download server
   - Try downloading during off-peak hours
   - Consider using wired connection instead of Wi-Fi

### Slow Download Speeds

**Problem:** Download is taking much longer than expected

**Solutions:**

1. **Use aria2c with multiple connections:**
   ```bash
   aria2c -x 16 -s 16 https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova
   ```

2. **Check available bandwidth:**
   - Close other applications using network
   - Pause other downloads
   - Test internet speed: `curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py | python -`

3. **Try different download mirror:**
   - For pre-warmed builds: S3 should be fast globally
   - For standard builds: GitHub releases use CDN

4. **Schedule download during off-peak hours:**
   - For 80-100 GB files, overnight downloads recommended
   - Use `nohup` to keep download running:
     ```bash
     nohup wget -c https://hedgehog-lab-artifacts.s3.us-east-1.amazonaws.com/releases/v0.2.0/hedgehog-lab-prewarmed-0.2.0.ova &
     ```

### Browser Limitations for Large Files

**Problem:** Browser fails to download or hangs on large files (especially 80-100 GB pre-warmed builds)

**Solution:** Use command-line tools instead of browser

- Browsers have memory limitations for large files
- May not support resume for interrupted downloads
- Command-line tools (wget, curl, aria2c) are more reliable

**Workaround for Windows users without WSL:**

1. **Install Git for Windows** (includes Git Bash with wget/curl)
2. **Use PowerShell with Invoke-WebRequest:**
   ```powershell
   Invoke-WebRequest -Uri "https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova" -OutFile "hedgehog-lab-standard-0.1.0.ova"
   ```

### Checksum Verification Fails

**Problem:** Checksum does not match expected value

**Causes and Solutions:**

1. **Incomplete download:**
   - Delete the file and re-download completely
   - Use resume-capable tool (wget -c, curl -C -)

2. **Corrupted download:**
   - Verify file size matches expected size
   - Re-download from beginning

3. **Wrong checksum file:**
   - Ensure checksum file matches the OVA version
   - Re-download both OVA and checksum file

4. **File modified after download:**
   - Do not edit or move the file before verification
   - Re-download if file was modified

### Out of Disk Space

**Problem:** Download fails with "No space left on device" error

**Solutions:**

1. **Check available space:**
   ```bash
   df -h .
   ```

2. **Free up space:**
   - Delete unnecessary files
   - Move other files to external storage
   - Consider downloading to external drive

3. **Download to different location:**
   ```bash
   # Specify output directory with more space
   wget -P /path/to/larger/disk https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
   ```

### Permission Denied

**Problem:** Cannot save file to download location

**Solutions:**

1. **Check write permissions:**
   ```bash
   ls -ld .
   ```

2. **Download to writable location:**
   ```bash
   cd ~/Downloads
   wget https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
   ```

3. **Run with appropriate permissions:**
   ```bash
   # Do NOT use sudo for downloads unless absolutely necessary
   # Instead, change to a directory you own
   cd ~
   mkdir -p hedgehog-lab-downloads
   cd hedgehog-lab-downloads
   wget https://github.com/afewell-hh/labapp/releases/download/v0.1.0/hedgehog-lab-standard-0.1.0.ova
   ```

## Download Size Comparison

| Build Type | Compressed Size | First Boot Time | Use Case | Download Time* |
|------------|----------------|-----------------|----------|----------------|
| **Standard** | 15-20 GB | 15-20 minutes | Self-paced learning, development | 30-60 minutes |
| **Pre-warmed** | 80-100 GB | 2-3 minutes | Workshops, training events, demos | 2-4 hours |

\* Download times assume 100 Mbps connection. Actual times vary based on internet speed.

### Why Choose Standard Build?

- Smaller download size (15-20 GB)
- Faster to distribute
- Easier to store and backup
- Suitable for individual learning
- One-time 15-20 minute first-boot initialization

### Why Choose Pre-warmed Build?

- Fastest first-boot experience (2-3 minutes)
- Ideal for workshops with many participants
- No internet dependency during first boot
- Pre-pulled container images
- Pre-initialized lab environment

## System Requirements

### For Standard Build

**Host System:**
- CPU: 4+ cores with virtualization (Intel VT-x/AMD-V)
- RAM: 20 GB total (4 GB host + 16 GB VM)
- Disk: 120 GB free space
- Network: Internet connection for first boot

**VM Configuration:**
- vCPUs: 8
- Memory: 16 GB
- Disk: 100 GB (dynamically allocated)
- Network: 1 adapter (NAT or Bridged)

### For Pre-warmed Build

**Host System:**
- CPU: 8+ cores with virtualization (Intel VT-x/AMD-V)
- RAM: 32 GB total (16 GB host + 16 GB VM)
- Disk: 200 GB free space (100 GB for OVA + extraction)
- Network: Internet connection (minimal, for updates only)

**VM Configuration:**
- vCPUs: 8
- Memory: 16 GB
- Disk: 100 GB (dynamically allocated)
- Network: 1 adapter (NAT or Bridged)

## Next Steps

After downloading and verifying your OVA:

1. **Import into hypervisor:** Follow [Installation Guide](INSTALL.md)
2. **First boot:** See [Quick Start Guide](QUICKSTART.md)
3. **Troubleshooting:** Check [Troubleshooting Guide](TROUBLESHOOTING.md)
4. **FAQ:** Review [Frequently Asked Questions](FAQ.md)

## Related Documentation

- [Installation Guide](INSTALL.md) - Import OVA into VMware/VirtualBox
- [Quick Start Guide](QUICKSTART.md) - First boot and getting started
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Common issues and solutions
- [FAQ](FAQ.md) - Frequently asked questions
- [Release Process](RELEASE_PROCESS.md) - How releases are created

## Support

**Found an issue?** [Report a bug](https://github.com/afewell-hh/labapp/issues)
**Have questions?** [Start a discussion](https://github.com/afewell-hh/labapp/discussions)
**Need help?** Check the [Troubleshooting Guide](TROUBLESHOOTING.md)

---

**Last Updated:** November 7, 2025
**Version:** 1.0
