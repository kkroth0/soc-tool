# 🛡️ SOC Forge v2.0

**SOC Forge** is an advanced IP threat intelligence platform designed for Security Operations Center (SOC) analysts. It provides comprehensive IP analysis across multiple threat intelligence sources with an intuitive CLI interface, automated reporting, and advanced analytics capabilities.

## ✨ Key Features

### 🔍 **Multi-Source Intelligence Analysis**
- **VirusTotal** - Malware detection and reputation scoring
- **AbuseIPDB** - Abuse reporting and confidence metrics
- **GreyNoise** - Internet scanning behavior analysis
- **ThreatFox** - IOC correlation and malware family attribution
- **IPInfo** - Geolocation and network infrastructure analysis

### 🎯 **Advanced IP Processing**
- **Smart IP Extraction** - Automatically detects IPs from any format
- **Flexible Input Support** - Comma-separated, line-separated, with ports, prefixes, etc.
- **Private IP Filtering** - Intelligent filtering of internal/private ranges
- **Duplicate Detection** - Automatic deduplication with statistics

### 👨‍💻 **SOC Analyst-Focused Interface**
- **Context-Aware CLI** - Human-readable interface with threat-focused workflows
- **Real-Time Progress** - Live analysis progress with source-by-source updates  
- **Risk Assessment** - Automated threat scoring and prioritization
- **Actionable Insights** - Clear recommendations for each finding

### 📊 **Comprehensive Reporting**
- **Executive Summaries** - High-level risk assessments for management
- **Technical Reports** - Detailed findings for security teams
- **KQL Query Generation** - Ready-to-use queries for SIEM platforms
- **JSON Export** - Machine-readable results for automation

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Internet connection for API queries
- API keys from threat intelligence sources

### Installation

1. **Clone and Setup**
```bash
git clone https://github.com/yourusername/soc-forge.git
cd soc-forge
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

2. **Configure API Keys**
```bash
cp .env.example .env
# Edit .env with your actual API keys
```

3. **Run SOC Forge**
```bash
python soc_forge.py
```

## 🔧 Configuration

### API Key Setup

Edit the `.env` file with your API keys:

```env
# Required for malware analysis
VIRUSTOTAL_API_KEY=your_virustotal_key_here

# Required for abuse intelligence  
ABUSEIPDB_API_KEY=your_abuseipdb_key_here

# Required for geolocation data
IPINFO_API_KEY=your_ipinfo_key_here

# Required for IOC correlation
THREATFOX_API_KEY=your_threatfox_key_here

# Required for noise classification
GREYNOISE_API_KEY=your_greynoise_key_here
```

### Get API Keys
- [VirusTotal](https://www.virustotal.com/gui/join-us) - Free tier available
- [AbuseIPDB](https://www.abuseipdb.com/account/api) - Free tier available  
- [IPInfo](https://ipinfo.io/signup) - Free tier available
- [ThreatFox](https://threatfox.abuse.ch/api/) - Free API
- [GreyNoise](https://www.greynoise.io/viz/signup) - Free tier available

## 📖 Usage Guide

### Basic Analysis Workflow

1. **Launch SOC Forge**
```bash
python soc_forge.py
```

2. **Input Target IPs**
- Supports multiple formats automatically
- Examples:
  ```
  8.8.8.8, 1.1.1.1, 208.67.222.222
  192.168.1.1:80
  IP: 10.0.0.1 (suspicious)
  185.220.100.240
  malicious-server.com 203.0.113.1
  ```

3. **Choose Analysis Type**
- **Quick Assessment** - Fast threat triage
- **Comprehensive Analysis** - Full multi-source analysis
- **Malware Focus** - VirusTotal + ThreatFox analysis
- **Network Intel** - Geographic and infrastructure analysis

4. **Review Results**
- Threat scoring and risk levels
- Source-by-source findings
- Actionable recommendations

5. **Generate Reports**
- Executive summaries for management
- Technical reports for SOC teams
- KQL queries for SIEM integration

### Advanced Features

#### KQL Query Generation
Automatically generates security analytics queries:
- Source IP monitoring
- Destination IP analysis  
- Network traffic patterns
- Security event correlation

#### Threat Intelligence Correlation
Cross-references findings across all sources:
- Malware family attribution
- Campaign tracking
- Actor profiling
- IOC timeline analysis

## 🏗️ Architecture

```
soc-forge/
├── soc_forge.py              # Main application entry point
├── src/soc_forge/
│   ├── apis/                 # Threat intelligence API clients
│   │   ├── virustotal.py     
│   │   ├── abuseipdb.py
│   │   ├── greynoise.py
│   │   ├── threatfox.py
│   │   └── ipinfo.py
│   ├── cli/                  # User interface components
│   │   └── interface.py      # SOC analyst-focused CLI
│   ├── core/                 # Core analysis engine
│   │   ├── analyzer.py       # Multi-source analysis orchestration
│   │   └── ip_parser.py      # Advanced IP extraction & validation
│   ├── reports/              # Report generation
│   │   └── generator.py      # PDF, JSON report creation
│   └── utils/                # Utilities
│       └── kql_generator.py  # SIEM query generation
├── outputs/                  # Generated reports and logs
│   ├── reports/              
│   └── logs/
└── config/                   # Configuration files
```

## 🔒 Security Considerations

- **API Key Protection** - Keys are loaded from environment variables
- **Rate Limiting** - Built-in respect for API rate limits
- **Private IP Filtering** - Prevents accidental analysis of internal infrastructure
- **Audit Logging** - Complete analysis activity logging
- **Confidential Reports** - Generated reports marked as confidential

## 🤝 Contributing

We welcome contributions from the security community!

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)  
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Code formatting
black src/
flake8 src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Threat Intelligence Providers** - VirusTotal, AbuseIPDB, GreyNoise, ThreatFox, IPInfo
- **SOC Community** - Built by SOC analysts for SOC analysts
- **Open Source Libraries** - Rich CLI framework, ReportLab PDF generation

## 📞 Support

- **Issues** - [GitHub Issues](https://github.com/yourusername/soc-forge/issues)
- **Documentation** - [Wiki](https://github.com/yourusername/soc-forge/wiki)
- **Security** - Report security issues privately via email

---

*SOC Forge v2.0 - Empowering SOC analysts with advanced threat intelligence*