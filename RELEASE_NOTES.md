# Vibe-DNS Release Build Information

This repository includes an automated build pipeline (`.github/workflows/build.yml`) that generates standalone binaries for the following platforms:

## Supported Platforms

**Linux**<BR>
AMD64 (x86_64) (`vibe-dns-server-linux-amd64`)<BR>
Built on Debian 10 (Buster) for maximum compatibility (glibc 2.28+). Works on Ubuntu 18.04+, RHEL 8+, etc.<BR>
<BR>
**macOS**<BR>
ARM64 (Apple Silicon) (`vibe-dns-server-macos-arm64`).<BR>
Built on macOS 14. Requires Apple Silicon M1-M5.<BR>

## Build Artifacts

When a release is tagged, the following assets are automatically published:

1. **Server Executable:** The main DNS server binary.

2. **GeoIP Compiler:** A standalone tool (`geoip-compiler-*`) to generate the required `.vibe` database files.

3. **Default Configs:** `config.yaml`, `categories.json`, and `geoip.txt`.

## How to Build Locally

If you prefer to build the binaries yourself instead of downloading them:

1. Install Python 3.11+ and dependencies.

2. Install PyInstaller: `pip install pyinstaller`.

3. Run the build command:

   ```
   pyinstaller --clean --onefile --name vibe-dns-server server.py
   pyinstaller --clean --onefile --name geoip-compiler geoip_compiler.py
   
   ```

4. Binaries will be located on the [Releases](https://github.com/cbuijs/vibe-dns/releases) page.
