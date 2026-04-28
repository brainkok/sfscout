# SFScout

A security auditing and data exfiltration tool for Salesforce Experience Cloud. Enumerates accessible objects and records, dumps all retrievable data to disk, checks API exposure, and detects common misconfigurations in both Guest and Authenticated contexts.

## Features

- Accessible record enumeration via Aura and GraphQL
- CRUD permission checking per object
- Self-registration detection
- REST and SOAP API exposure checks
- UI record list discovery
- Object home URL discovery
- Custom Apex controller enumeration
- CSP trusted site collection
- **HTML report generation** (`--html`)

## Installation

Requires Python 3.10+.

```
git clone <repo-url>
cd sfscout
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```
python sfscout.py -h
```

### Guest context (unauthenticated)

```
python sfscout.py -u https://target.my.salesforce.com -o ./output --html
```

### Authenticated context

Supply session cookies:

```
python sfscout.py -u https://target.my.salesforce.com -c "sid=ABC123; ..." -o ./output --html
```

Or provide a captured raw HTTP request file:

```
python sfscout.py -r request.txt -o ./output --html
```

## Options

| Flag | Description |
|------|-------------|
| `-u` | Root URL of the Salesforce application |
| `-c` | Session cookies (copy from browser devtools) |
| `-o` | Output directory for saved results |
| `-l` | Comma-separated list of objects to target |
| `-d` | Enable debug output |
| `-v` | Enable verbose output |
| `-p` | HTTP/S proxy (e.g. `http://127.0.0.1:8080`) |
| `-k` | Skip TLS certificate validation |
| `--app` | App path override (e.g. `/myApp`) |
| `--aura` | Aura endpoint path override (e.g. `/aura`) |
| `--no-gql` | Disable GraphQL checks |
| `--html` | Generate an HTML report (requires `-o`) |
| `--no-banner` | Suppress the ASCII banner |
| `-r` | Path to a captured raw HTTP request file |

## Output structure

```
output/
  report.html               # HTML report (with --html)
  records/
    summary.txt
    Account.json
    Contact.json
  gql_records/
    summary.txt
    Account.json
  custom_controllers.json
  csp_trusted_sites.json
  recordlists.json
  homeurls.json
  permissions.json
```

## Multiple apps

A single Salesforce instance may host multiple Experience Cloud apps (e.g. `/myApp/s`). Use `--app /myApp` to target a specific one, and run the tool separately per app.

## Ethical Use Disclaimer

This project is provided for educational, research, and defensive security purposes only.

You agree NOT to use this tool for:
- Unauthorized access to systems or data
- Any illegal activity
- Harassment, exploitation, or harm of individuals or organizations

The author assumes no liability and is not responsible for any misuse or damages caused by this software.

Use at your own risk.

## Credits

This project is based on prior work by Google LLC, licensed under the Apache License 2.0.

Significant modifications and extensions have been made, including:
- Rewritten core logic (AuraProbe)
- Record extraction and pagination
- Permission analysis (CRUD)
- HTML report generation
- Improved endpoint and context discovery
- Enhanced logging and error handling

## License

This project is licensed under the Apache License 2.0.

- Original portions: Copyright 2025 Google LLC  
- Modifications: Copyright 2026 Brain Kok

See the LICENSE file for details.
