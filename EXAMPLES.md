# Quick Start Examples

## 1. Minimal Setup (Source)

1. **Initialize Environment**

   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   
   ```

2. **Compile GeoIP Data**
   *You need a source JSON file. For testing, you can try fetching a sample or using a token.*

   ```
   # Assuming you have ipinfo_lite.json
   python3 geoip_compiler.py --json ipinfo_lite.json --unified-output geoip.vibe
   
   ```

3. **Run Server**

   ```
   sudo python3 server.py --config full_config.yaml
   
   ```

## 2. Docker Compose (Conceptual)

Create a `docker-compose.yml`:

```
version: '3'
services:
  vibe-dns:
    image: python:3.11-slim
    volumes:
      - ./:/app
    working_dir: /app
    ports:
      - "53:53/udp"
      - "53:53/tcp"
    command: sh -c "pip install -r requirements.txt && python server.py"
    cap_add:
      - NET_ADMIN

```