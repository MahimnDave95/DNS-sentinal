# DNS Sentinull

DNS Sentinull is a cybersecurity project that monitors and filters DNS requests to help protect users from phishing, malicious, and unwanted websites. It checks requested domains against security rules or a custom blacklist and blocks unsafe domains before a connection is completed.

## Features

- Detects and blocks suspicious or malicious domains.
- Supports a custom domain blacklist.
- Monitors DNS requests.
- Logs blocked and allowed requests.
- Provides useful information for security analysis.
- Helps reduce exposure to phishing websites and malware.
- Designed for learning, testing, and authorized security environments.

## How It Works

1. A user requests access to a website.
2. The DNS request is received by DNS Sentinull.
3. The domain is checked against the blacklist and security rules.
4. If the domain is unsafe, the request is blocked.
5. If the domain is considered safe, the request is forwarded or allowed.
6. The result is saved in the activity log.

## Project Objective

The objective of DNS Sentinull is to create a simple and practical DNS security layer that improves protection against phishing, malware, and unwanted online content. The project also helps students understand DNS, domain filtering, network monitoring, and defensive cybersecurity.

## Suggested Project Structure

```text
DNS-Sentinull/
├── backend/              # DNS filtering and server logic
├── frontend/             # Optional monitoring dashboard
├── config/               # Configuration files and security rules
├── data/                 # Domain lists and local data
├── logs/                 # DNS activity and blocked-request logs
├── tests/                # Testing files
├── requirements.txt      # Python dependencies
├── .env.example          # Example environment configuration
└── README.md             # Project documentation
```

## Requirements

- Python 3.9 or later
- A Windows or Linux system
- Administrator/root permission for DNS or network configuration
- Internet connection for testing threat-intelligence sources, if configured

## Installation

Clone the repository:

```bash
git https://github.com/MahimnDave95/DNS-sentinal.git
cd dns-sentinull
```

Create and activate a virtual environment:

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy the example configuration file:

```bash
cp .env.example .env
```

On Windows, copy the file manually if the `cp` command is unavailable.

## Configuration

Configure the project using the `.env` file or the project configuration files. Typical settings may include:

```env
DNS_HOST=127.0.0.1
DNS_PORT=5353
LOG_LEVEL=INFO
BLACKLIST_FILE=data/blacklist.txt
LOG_FILE=logs/dns_sentinull.log
```

Do not commit passwords, API keys, private data, or production credentials to the repository.

## Running the Project

Start the DNS Sentinull service using the command supported by the implementation, for example:

```bash
python main.py
```

If the project includes a dashboard, start it using its documented command, for example:

```bash
python dashboard.py
```

The exact commands may differ depending on the final project structure.

## Adding Blocked Domains

Add one domain per line to the configured blacklist file:

```text
example-phishing-site.com
malicious-domain.test
unwanted-site.example
```

Use only domains from trusted sources or domains that you are authorized to block. Avoid blocking essential services without testing the impact first.

## Testing

Run the test suite with:

```bash
pytest
```

Test the project only on systems and networks that you own or have permission to administer. Use harmless test domains or a controlled local lab when verifying blocking behavior.

## Logging

DNS Sentinull can record information such as:

- Requested domain name
- Request time
- Allow or block decision
- Reason for the decision
- Client address, when appropriate and legally permitted

Logs should be protected because DNS activity may contain sensitive information.

## Security and Responsible Use

DNS Sentinull is intended for defensive cybersecurity, education, and authorized network administration. Do not use it to inspect, redirect, or interfere with networks without permission. Review local laws, institutional policies, and privacy requirements before deploying it.

DNS filtering is not a complete security solution. Users should also use updated operating systems, secure browsers, endpoint protection, strong authentication, and security awareness practices.

## Limitations

- A blacklist may not contain every newly created malicious domain.
- Domain-based filtering may not detect every harmful page on a trusted domain.
- Encrypted DNS and applications with their own DNS resolution may require additional configuration.
- Incorrect rules can block legitimate websites.
- Logs and threat-intelligence feeds require regular maintenance.

## Future Improvements

- Add a web-based monitoring dashboard.
- Support allowlists and rule categories.
- Add threat-intelligence feed updates.
- Provide notifications for repeated malicious requests.
- Add statistical reports and visualizations.
- Support encrypted DNS with careful privacy controls.
- Add unit, integration, and performance testing.
- Package the application for Windows and Linux.

## Disclaimer

DNS Sentinull is an educational and defensive security project. The developers are not responsible for misuse, unauthorized monitoring, service disruption, or damage caused by deploying or modifying the project.