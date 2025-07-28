# 🔐 Cracker Scanner 2025 — Laravel/API Env Exploiter

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║    ██████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗     ██████╗  ██████╗ ║
║   ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ╚════██╗██╔═████╗║
║   ██║     ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝     █████╔╝██║██╔██║║
║   ██║     ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ██╔═══╝ ████╔╝██║║
║   ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║    ███████╗╚██████╔╝║
║    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝ ║
║                                                                               ║
║                   🔐 Laravel/API Env Exploiter 2025 🔐                       ║
║                     All-In-One Post-Research Edition                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## ⚠️ **LEGAL DISCLAIMER**

**This tool is for authorized security testing and educational purposes only!**

- ✅ Use only on systems you own or have explicit written permission to test
- ❌ Unauthorized access to computer systems is illegal
- 🔒 Follow responsible disclosure practices
- 📚 Educational and research use only

## 🧠 **Project Overview**

Cracker Scanner 2025 is a professional, high-performance CLI tool designed for authorized Laravel vulnerability assessment and credential validation. Built for cybersecurity professionals, penetration testers, and security researchers.

### 🎯 **Primary Objectives**

- **Mass Laravel Scanning**: Efficiently scan thousands of targets for Laravel-specific vulnerabilities
- **Automated Secret Extraction**: Extract and categorize credentials from exposed files and API responses  
- **Live Credential Validation**: Test extracted credentials against live services (SMTP, AWS, SendGrid, etc.)
- **Professional Reporting**: Generate comprehensive reports in multiple formats
- **Real-time Notifications**: Telegram alerts for immediate threat awareness

## 🚀 **Key Features**

### 🔍 **Advanced Vulnerability Detection**
- **Laravel 2025 Vulnerabilities**:
  - `.env` file exposure detection
  - PHPUnit `eval-stdin.php` RCE vulnerability
  - Ignition Debug Mode RCE (CVE-2021-3129)
  - Laravel Telescope exposure
  - Laravel Horizon dashboard exposure
  - Debug bar and error page exposure
  - Log file exposure and analysis
  - Configuration file leakage

### 💎 **Comprehensive Secret Extraction**
- **SMTP Credentials**: Host, port, username, password extraction
- **Cloud Provider Keys**: AWS access keys, secret keys, regions, S3 buckets
- **Email Service APIs**: SendGrid, Mailgun, Mailjet API keys
- **Communication APIs**: Twilio, Vonage SMS/voice credentials
- **Payment Processing**: Stripe, PayPal API credentials
- **Database Connections**: MySQL, PostgreSQL, MongoDB, Redis URLs
- **Social Media APIs**: Facebook, Google, Twitter OAuth credentials

### 🔓 **Live Credential Validation**
- **SMTP Testing**: Direct SMTP authentication with TLS/SSL support
- **AWS Validation**: STS GetCallerIdentity API calls for credential verification
- **SendGrid API**: Account information endpoint testing
- **Mailgun API**: Domain and statistics endpoint validation
- **Twilio API**: Account information verification
- **Stripe API**: Account endpoint testing
- **Fallback Methods**: Raw socket connections when APIs unavailable

### 📊 **Professional Reporting & Export**
- **Multiple Formats**: JSON, CSV, TXT, XML export support
- **Comprehensive Reports**: Vulnerability summaries, credential validation results
- **Real-time Notifications**: Telegram bot integration with detailed alerts
- **Webhook Support**: Custom webhook notifications for CI/CD integration
- **Slack Integration**: Team notifications with formatted results

### ⚡ **High Performance Architecture**
- **Async/Await Design**: Python asyncio for maximum concurrency
- **Configurable Threading**: Up to 10,000 concurrent connections
- **Smart Rate Limiting**: Respectful scanning with configurable delays
- **Proxy Support**: HTTP/SOCKS proxy integration with rotation
- **Memory Efficient**: Streaming processing for large-scale scans
- **Fault Tolerant**: Retry logic and graceful error handling

## 📁 **Project Structure**

```
CrackerScanner2025/
│
├── cracker2025.py          # 🎯 Main CLI entry point
├── scanner.py              # 🔍 Laravel vulnerability scanner engine
├── extractor.py            # 💎 Secret and credential extraction module
├── checker.py              # 🔓 Live credential validation system
├── exporter.py             # 📊 Multi-format result export engine
├── telegram.py             # 📱 Telegram notification system
│
├── core/                   # 🏗️ Core framework modules
│   ├── __init__.py
│   ├── threads.py          # ⚡ Thread pool and async worker management
│   ├── http.py             # 🌐 Advanced HTTP client with proxy support
│   └── utils.py            # 🔧 Utilities, regex patterns, and helpers
│
├── data/                   # 📂 Scanning data and configurations
│   ├── paths.txt           # 📋 2500+ Laravel vulnerability paths
│   ├── targets.txt         # 🎯 Sample target list
│   └── fake_env.env        # 🧪 Test environment file
│
├── config.json             # ⚙️ Main configuration file
├── requirements.txt        # 📦 Python dependencies
├── README.md              # 📖 This documentation
└── LICENSE                # 📄 MIT License with security disclaimers
```

## 🛠️ **Installation & Setup**

### **Prerequisites**
- Python 3.7+ (3.9+ recommended)
- Linux/macOS/Windows (optimized for Linux VPS)
- 2GB+ RAM (4GB+ for large scans)
- 1GB+ free disk space

### **Quick Installation**

```bash
# Clone the repository
git clone https://github.com/wKayaa/xSeKaya.git
cd xSeKaya

# Install dependencies (optional - tool works with stdlib)
pip3 install -r requirements.txt

# Make executable
chmod +x cracker2025.py

# Test installation
python3 cracker2025.py --help
```

### **Docker Installation** (Optional)

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

ENTRYPOINT ["python3", "cracker2025.py"]
```

```bash
# Build and run with Docker
docker build -t cracker-scanner-2025 .
docker run -v $(pwd)/results:/app/results cracker-scanner-2025 -t example.com -q
```

## 🎮 **Usage Examples**

### **Basic Scanning**

```bash
# Quick scan single target
python3 cracker2025.py -t example.com -q

# Comprehensive deep scan
python3 cracker2025.py -t example.com --deep

# Scan multiple targets from file
python3 cracker2025.py -f data/targets.txt --threads 200
```

### **Advanced Scanning**

```bash
# CIDR range scanning
python3 cracker2025.py -t 192.168.1.0/24 --quick --threads 500

# Custom paths with proxy
python3 cracker2025.py -t target.com --paths custom_paths.txt --proxy socks5://127.0.0.1:9050

# High-performance scan with custom timeout
python3 cracker2025.py -f targets.txt --threads 1000 --timeout 5 --rate-limit 20
```

### **Output & Export Options**

```bash
# Multiple export formats
python3 cracker2025.py -t example.com --format json,csv,txt,xml

# Custom output directory
python3 cracker2025.py -t example.com -o /tmp/scan_results/

# Secrets-only export
python3 cracker2025.py -t example.com --secrets-only
```

### **Feature Control**

```bash
# Skip credential validation
python3 cracker2025.py -t example.com --no-check

# Skip secret extraction
python3 cracker2025.py -t example.com --no-extract

# Disable notifications
python3 cracker2025.py -t example.com --no-telegram
```

## ⚙️ **Configuration**

### **Main Configuration** (`config.json`)

```json
{
  "scanner": {
    "timeout": 10,
    "max_retries": 3,
    "max_workers": 100,
    "verify_ssl": false,
    "rate_limit": 10
  },
  "notifications": {
    "telegram": {
      "enabled": true,
      "bot_token": "YOUR_BOT_TOKEN",
      "chat_id": "YOUR_CHAT_ID"
    }
  }
}
```

### **Telegram Setup**

1. Create Telegram bot via [@BotFather](https://t.me/botfather)
2. Get bot token and chat ID
3. Update `config.json` with credentials
4. Enable notifications in config

```json
{
  "notifications": {
    "telegram": {
      "enabled": true,
      "bot_token": "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ",
      "chat_id": "-1001234567890",
      "notify_on_vulnerability": true,
      "notify_on_credentials": true
    }
  }
}
```

## 🔬 **Detection Capabilities**

### **Laravel-Specific Vulnerabilities**

| Vulnerability Type | Description | Risk Level |
|-------------------|-------------|------------|
| **ENV File Exposure** | `.env` files containing secrets | 🔴 Critical |
| **PHPUnit RCE** | `eval-stdin.php` remote code execution | 🔴 Critical |
| **Ignition RCE** | Debug mode remote code execution | 🔴 Critical |
| **Telescope Exposure** | Development tool exposure | 🟡 Medium |
| **Horizon Dashboard** | Queue dashboard exposure | 🟡 Medium |
| **Debug Information** | Error pages with sensitive data | 🟡 Medium |
| **Log File Access** | Application logs with credentials | 🟠 High |
| **Config Exposure** | Configuration files leakage | 🟠 High |

### **Credential Types Detected**

| Service Category | Examples | Validation Method |
|-----------------|----------|-------------------|
| **Email/SMTP** | Gmail, Outlook, Mailtrap | SMTP Authentication |
| **Cloud Providers** | AWS, Google Cloud, Azure | API Authentication |
| **Email Services** | SendGrid, Mailgun, Mailjet | REST API Calls |
| **Communication** | Twilio, Vonage, Nexmo | API Verification |
| **Payment** | Stripe, PayPal, Square | Account Endpoints |
| **Databases** | MySQL, PostgreSQL, MongoDB | Connection Testing |
| **Social Media** | Facebook, Twitter, Google | OAuth Validation |

## 📈 **Performance Benchmarks**

### **Scanning Performance**
- **Single Target**: ~500 paths in 30-60 seconds
- **100 Targets**: ~50,000 requests in 10-15 minutes  
- **1000 Targets**: ~500,000 requests in 2-3 hours
- **Maximum Throughput**: 10,000 concurrent connections

### **Memory Usage**
- **Base Usage**: ~50-100MB
- **Large Scans**: ~200-500MB  
- **Peak Usage**: <1GB (10,000 targets)

### **Network Efficiency**
- **Request Size**: Minimal HTTP overhead
- **Retry Logic**: Smart backoff for failed requests
- **Rate Limiting**: Configurable per-target limits
- **Proxy Support**: Rotation and failover

## 🔧 **Advanced Configuration**

### **Custom Vulnerability Paths**

Create custom `paths.txt` file:
```
.env
.env.backup  
vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
_ignition/execute-solution
custom/application/path
```

### **Proxy Configuration**

```json
{
  "network": {
    "proxy": "socks5://127.0.0.1:9050",
    "proxy_rotation": true,
    "proxy_list": [
      "http://proxy1:8080",
      "socks5://proxy2:1080"
    ]
  }
}
```

### **Rate Limiting & Performance**

```json
{
  "scanner": {
    "max_workers": 500,
    "rate_limit": 20,
    "timeout": 15,
    "max_retries": 5
  }
}
```

## 🛡️ **Security & Ethics**

### **Responsible Usage Guidelines**

1. **Authorization Required**: Only scan systems you own or have explicit permission to test
2. **Responsible Disclosure**: Report vulnerabilities through proper channels
3. **Rate Limiting**: Use appropriate delays to avoid service disruption
4. **Data Handling**: Securely handle and dispose of extracted credentials
5. **Legal Compliance**: Ensure compliance with local and international laws

### **Built-in Safety Features**

- **Rate Limiting**: Prevents overwhelming target systems
- **Timeout Controls**: Avoids hanging connections
- **Retry Logic**: Graceful handling of network issues  
- **Error Handling**: Comprehensive exception management
- **Logging**: Detailed audit trails for security reviews

## 🤝 **Contributing**

### **Development Setup**

```bash
# Clone repository
git clone https://github.com/wKayaa/xSeKaya.git
cd xSeKaya

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements.txt

# Run tests
python3 -m pytest tests/
```

### **Contribution Guidelines**

1. **Security First**: All contributions must maintain security best practices
2. **Documentation**: Update README and inline docs for new features
3. **Testing**: Include tests for new functionality
4. **Ethics**: Ensure contributions align with ethical hacking principles
5. **Performance**: Maintain or improve scanning performance

## 📋 **Roadmap**

### **Version 1.1 (Q2 2025)**
- [ ] Additional Laravel vulnerability signatures
- [ ] WordPress and Drupal support
- [ ] Database credential testing
- [ ] Enhanced proxy rotation
- [ ] Web interface dashboard

### **Version 1.2 (Q3 2025)**
- [ ] Machine learning vulnerability detection
- [ ] Custom exploitation modules
- [ ] Advanced reporting analytics
- [ ] Multi-tenant scanning
- [ ] API integration framework

## 🐛 **Troubleshooting**

### **Common Issues**

**"No valid targets found"**
```bash
# Check target format
python3 cracker2025.py -t https://example.com  # Include protocol
```

**"Connection timeout"**
```bash
# Increase timeout
python3 cracker2025.py -t example.com --timeout 30
```

**"Too many open files"**
```bash
# Reduce concurrent threads
python3 cracker2025.py -t example.com --threads 50
```

### **Performance Optimization**

```bash
# For VPS/Cloud deployment
ulimit -n 65536  # Increase file descriptors
echo 'net.core.somaxconn = 65536' >> /etc/sysctl.conf
```

## 📞 **Support & Community**

- **GitHub Issues**: [Report bugs and feature requests](https://github.com/wKayaa/xSeKaya/issues)
- **Security Issues**: Contact privately for security vulnerabilities
- **Documentation**: Check wiki for detailed guides
- **Community**: Join discussions in GitHub Discussions

## 📄 **License & Legal**

This project is licensed under the MIT License with additional security disclaimers. See [LICENSE](LICENSE) file for details.

**Important**: This tool is provided for educational and authorized testing purposes only. Users are solely responsible for ensuring lawful and ethical use.

---

<div align="center">

**🔐 Built for Security Professionals | 🧠 Powered by Python | ⚡ Optimized for Performance**

*Made with ❤️ for the cybersecurity community*

**⭐ Star this repo if you find it useful! ⭐**

</div>