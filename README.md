# vibe-dns (TESTING - USE AT OWN RISK)


## **1. Introduction**

This is a high-performance, modular Filtering DNS Server written in Python. It supports modern DNS protocols, granular policy enforcement, and robust network management features.

### **Key Features**

* **Protocols**: UDP, TCP, DoT (DNS over TLS), DoH (DNS over HTTPS).  
* **Filtering**: Domain (Trie-based), Regex, IP/CIDR, and Record Type filtering.  
* **IPv6 Support**: Fully integrated for listening, upstream resolution, and rate limiting.  
* **Client Management**: Identification via IP, CIDR, MAC address, TLS SNI, or HTTP Path.  
* **Performance**: In-memory caching, request deduplication, and asynchronous I/O.  
* **Rate Limiting**: Subnet-aware limiting with UDP truncation and total drop thresholds.

## **2. Installation**

### **Prerequisites**

* **Python 3.7+**  
* **Linux** (Recommended for full feature set like ip neigh MAC lookups and Syslog).

### **Step 1: Install Dependencies**

Install the required Python packages using the provided requirements file:
```
pip install -r requirements.txt
```
### **Step 2: Generate TLS Certificates (Required for DoT/DoH)**

If you do not have real certificates, generate self-signed ones for testing:
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=dns.example.com"
```
*Place `cert.pem` and `key.pem` in the project root or update `config.yaml` paths.*

### **Step 3: Run the Server**

Since the server binds to privileged ports (53, 443, 853), it usually requires root privileges:
```
sudo python3 server.py
```
**Command Line Options:**

* `-c` or `--config` : Specify a custom configuration file path. Default is `config.yaml`.
```
sudo python3 server.py -c /etc/dns-filter/production.yaml
```

## **Directory Structure**

Ensure your project directory looks like this:
```
/project-root  
├── server.py           # Main entry point  
├── config.yaml         # Configuration  
├── requirements.txt    # Dependencies  
├── utils.py            # Logging & Helpers  
├── filtering.py        # Rule Engine  
├── resolver.py         # DNS Logic  
├── cert.pem            # TLS Certificate  
└── key.pem             # TLS Private Key  
```
