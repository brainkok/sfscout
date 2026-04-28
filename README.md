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

### pipx (recommended)

```
pipx install .
```

### Manual

Requires Python 3.10+.

```
git clone <repo-url>
cd sfscout
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux / macOS
pip install -r requirements.txt
```

## Usage

```
python src/sfscout.py -h
```

### Guest context (unauthenticated)

```
python src/sfscout.py -u https://target.my.salesforce.com -o ./output --html
```

### Authenticated context

Supply session cookies:

```
python src/sfscout.py -u https://target.my.salesforce.com -c "sid=ABC123; ..." -o ./output --html
```

Or provide a captured raw HTTP request file:

```
python src/sfscout.py -r request.txt -o ./output --html
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
