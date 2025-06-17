# SOC-Forge

SOC-Forge is a powerful CLI tool designed for SOC analysts to analyze IP addresses using multiple threat intelligence sources. It provides easy-to-use interfaces for IP analysis, KQL query generation, and detailed report creation.

## Features

- 🔍 **IP Analysis**: Analyze IPs using multiple threat intelligence sources:
  - VirusTotal
  - AbuseIPDB
  - IPInfo
- 📊 **Interactive Interface**: User-friendly CLI with colored output
- 🔎 **KQL Query Generation**: Generate Kibana queries for source IPs, destination IPs, or both
- 📝 **Detailed Reports**: Generate comprehensive analysis reports
- 🛠️ **Easy Setup**: Simple installation process with batch scripts

## Installation

1. Clone this repository:
```powershell
git clone https://github.com/yourusername/soc-forge.git
cd soc-forge
```

2. Run the installation script:
```powershell
.\install.bat
```

3. Configure your API keys:
   - Copy `.env.example` to `.env`
   - Replace the placeholder API keys with your actual keys from:
     - [VirusTotal](https://www.virustotal.com/gui/join-us)
     - [AbuseIPDB](https://www.abuseipdb.com/account/api)
     - [IPInfo](https://ipinfo.io/signup)

## Usage

1. Run the main script:
```powershell
python query.py
```

2. Use the interactive menu to:
   - Input IP addresses (supports multiple formats)
   - List extracted IPs
   - Analyze IPs using various services
   - Generate KQL queries
   - Create detailed analysis reports

## Distribution

To create a distributable package:

```powershell
.\package.bat
```

This will create a ZIP file containing all necessary files for distribution.

## Dependencies

All required packages are listed in `requirements.txt` and will be installed automatically by the installation script:

- python-dotenv
- requests
- rich
- [other dependencies]

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to VirusTotal, AbuseIPDB, and IPInfo for their excellent APIs
- Built for SOC analysts by SOC analysts
