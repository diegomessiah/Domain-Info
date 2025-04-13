# Domain Info

A lightweight Python tool to extract key information about internet domains. Ideal for security analysts, system administrators, or anyone needing to gather DNS, IP, and SSL details quickly.

## 🔍 Features

- Retrieves DNS and IP resolution
- Gathers SSL certificate details
- Performs WHOIS and basic network lookups
- Outputs clear and human-readable results

## 📦 Requirements

- Python 3.6+
- Modules:
  - `socket`
  - `ssl`
  - `requests`
  - `whois` *(optional)*

Install optional packages:

```bash
pip install requests python-whois
```
## 🚀 Usage

```bash
python domain_info.py example.com
```
Output will include:
  - Domain IP and DNS resolution
  - SSL certificate subject/issuer
  - Expiry date
  - WHOIS info (if available)

## 📁 Example Output
See the examples/ folder for sample output.

## 🛡️ Use Cases
- Blue Team analysis
- Security audits
- Educational purposes
- General domain investigation

## 📄 License
This project is licensed under the MIT License.

## 🙋‍♂️ Author
Diego Messiah
