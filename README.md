# SenseScan

SenseScan is a sensitive data scanner for source code, PDFs, Office documents, and image metadata. It identifies exposed secrets, credentials, tokens, private keys, emails, internal paths, API endpoints, infrastructure details, and other potentially sensitive information.

It uses pattern-based detection with value validation and filtering to reduce false positives, and generates reports in multiple formats for further analysis.

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-2.0.0-blue)]()
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## Features

- **Secret detection** – API keys, access tokens, passwords, credentials, JWTs, and private keys
- **Cloud & service tokens** – AWS, GCP, GitHub, GitLab, Slack, Stripe, SendGrid, Twilio, npm, PyPI, and more
- **Database discovery** – Connection strings, database URLs, Redis, MySQL, PostgreSQL, MongoDB, and other services
- **Personal information** – Email addresses, usernames, and phone numbers
- **Network information** – IPv4, IPv6, URLs, and API endpoints
- **Internal path discovery** – Relative paths, module paths, Windows paths, and Unix system paths
- **Infrastructure discovery** – Docker images, AWS ARNs, Kubernetes resources, and API versions
- **Technology fingerprinting** – Frameworks, libraries, package versions, and technology references
- **PDF analysis** – Extracts document text, metadata, links, and form field values
- **Office document analysis** – Extracts text and document properties from DOCX, XLSX, PPTX, ODT, ODS, and ODP files
- **Image metadata analysis** – Extracts EXIF, GPS, camera information, and embedded text metadata
- **Value validation** – Filters common placeholders, invalid values, and code references
- **Duplicate detection** – Skips identical files using size comparison and SHA-256 hashing
- **Category filtering** – Exclude specific finding categories or values using custom regular expressions
- **Multiple report formats** – Text, JSON, and HTML reports
- **CI integration** – Optional non-zero exit code when findings are detected

---

## Requirements

- Python 3.12+

Optional dependencies:

- `pypdf` – PDF text and metadata extraction
- `Pillow` – Image metadata extraction
- `colorama` – Windows console colors

Install dependencies:

```bash
pip install pypdf pillow colorama
```

The scanner works without optional dependencies, but PDF and image metadata extraction will be disabled when their respective libraries are missing.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Mehran-Seifalinia/SenseScan.git
cd SenseScan
```

### 2. Install optional dependencies

```bash
pip install -r requirements.txt
```

### 3. Run SenseScan

```bash
python SenseScan.py
```

---

## Usage

### Basic usage

Scan JavaScript files in the current directory:

```bash
python SenseScan.py
```

Scan a specific file:

```bash
python SenseScan.py -p config.py
```

Scan a directory:

```bash
python SenseScan.py -p ./project -r -a
```

### Scan specific extensions

```bash
python SenseScan.py -p ./project -r --ext js,ts,py,json,yaml
```

### Generate reports

JSON:

```bash
python SenseScan.py -p ./project -r -a --format json -o results.json
```

HTML:

```bash
python SenseScan.py -p ./project -r -a --format html -o report.html
```

Text:

```bash
python SenseScan.py -p ./project -r -a --format text -o report.txt
```

### CI mode

Return exit code `1` when findings are detected:

```bash
python SenseScan.py -p ./project -r -a --fail-on-findings
```

---

## Command Line Arguments

| Argument | Description |
|---|---|
| `-p, --path` | File or directory to scan (default: current directory) |
| `-r, --recursive` | Recursively scan subdirectories |
| `-a, --all` | Scan all supported file types |
| `--ext` | Comma-separated extensions to scan (e.g. `js,ts,py,json`) |
| `--max-size` | Maximum file size (default: `50MB`) |
| `--exclude` | Comma-separated finding categories to exclude |
| `--exclude-pattern` | Comma-separated regular expressions to exclude matching values |
| `--no-dedupe` | Disable duplicate file detection |
| `--no-default-excludes` | Include normally excluded directories such as `.git` and `node_modules` |
| `-v` | Increase verbosity (`-v`, `-vv`, `-vvv`, `-vvvv`) |
| `--verbose` | Set verbosity level explicitly (`0-4`) |
| `--output` | Save the report to a file |
| `--format` | Report format: `text`, `json`, or `html` |
| `--fail-on-findings` | Exit with code `1` when findings exist (useful for CI) |
| `--no-color` | Disable ANSI colors |
| `--version` | Display tool version |

---

## Supported File Types

| Type | Extensions | Analysis |
|---|---|---|
| Source code & text | JS, JSX, TS, TSX, Python, Java, Go, PHP, C/C++, C#, Ruby, Rust, Swift, HTML, CSS, JSON, YAML, XML, SQL, Shell, and more | Content scanning |
| PDF | `.pdf` | Text, metadata, links, and form fields |
| Office | `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.odp` | Document text, XML relationships, and metadata |
| Images | `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`, `.webp`, `.tif`, `.tiff`, `.heic`, `.heif`, `.ico` | EXIF, GPS, and embedded metadata |

Compressed archives are skipped and are not extracted or scanned.

---

## Detection Categories

| Category | Examples |
|---|---|
| `credentials` | Passwords, connection strings, and authentication credentials |
| `tokens` | AWS, GitHub, GitLab, Slack, Stripe, JWT, and API tokens |
| `private_keys` | RSA, EC, DSA, OpenSSH, PGP, and certificates |
| `database` | Database URLs and connection information |
| `usernames` | Usernames and account identifiers |
| `emails` | Email addresses |
| `phone_numbers` | Iranian and international phone numbers |
| `ips` | IPv4 and IPv6 addresses |
| `urls` | HTTP and HTTPS URLs |
| `files` | References to potentially sensitive files |
| `paths_internal` | Relative paths, module paths, and internal routes |
| `paths_system` | Windows and Unix system paths |
| `api_endpoints_complete` | API endpoints with HTTP methods |
| `api_endpoints_partial` | API paths without a known HTTP method |
| `errors` | Exceptions, stack traces, and error messages |
| `technology` | Frameworks, libraries, and version references |
| `infrastructure` | Docker, AWS, and Kubernetes information |
| `env_vars` | Sensitive environment variable references |
| `storage` | Local storage, session storage, and cookie references |
| `metadata` | Sensitive document and image metadata |
| `other` | Additional categorized findings |

---

## Configuration Examples

### Exclude categories

Skip email and technology findings:

```bash
python SenseScan.py -p ./project -r -a --exclude emails,technology
```

### Exclude specific values

Ignore values matching custom regular expressions:

```bash
python SenseScan.py -p ./project -r -a --exclude-pattern "example\.com,test-token"
```

### Adjust maximum file size

```bash
python SenseScan.py -p ./project -r -a --max-size 100MB
```

### Increase verbosity

```bash
python SenseScan.py -p ./project -r -a -vvv
```

### Include normally excluded directories

```bash
python SenseScan.py -p ./project -r -a --no-default-excludes
```

---

## Default Behavior

- Without `-a` or `--ext`, only `.js` files are selected.
- Without `-r`, only files directly inside the specified directory are scanned.
- With `-r`, common dependency and cache directories are excluded by default.
- Files larger than `50MB` are skipped by default.
- Identical files are detected and skipped by default.
- Compressed archives are not extracted or scanned.
- Images are not OCR-processed; only their metadata is inspected.
- PDF and image extraction require their respective optional dependencies.
- Build and distribution directories are not automatically excluded.

---

## Output Formats

SenseScan supports three report formats:

| Format | Description |
|---|---|
| `text` | Console-friendly report with categorized findings and file locations |
| `json` | Structured report containing metadata, options, summaries, findings, and errors |
| `html` | Interactive HTML report with categorized findings and filtering |

Findings include:

- Category and detection type
- Matched sensitive value
- File path
- Line and column information when available
- Source information (content or metadata)
- Context preview
- Occurrence locations

Duplicate findings are aggregated to avoid reporting the same value repeatedly.

---

## Exit Codes

| Code | Description |
|---|---|
| `0` | Scan completed successfully |
| `1` | Findings detected (when `--fail-on-findings` is enabled) |
| `2` | Execution error |
| `3` | No files matched the selected filters |
| `130` | Scan interrupted by the user |

---

## Limitations

- **Pattern-based detection** – Uses predefined regular expressions and validators. Unknown secret formats may be missed.
- **False positives** – Validation reduces noise but cannot guarantee that every finding is a real secret.
- **No OCR** – Images are inspected for metadata only; text inside image pixels is not analyzed.
- **Archive handling** – ZIP, TAR, GZIP, JAR, APK, and other supported archive extensions are skipped without extraction.
- **Encrypted PDFs** – Password-protected PDFs cannot be extracted unless they can be opened with an empty password.
- **Optional dependencies** – PDF and image analysis are unavailable without `pypdf` and `Pillow`, respectively.
- **File size limit** – Files exceeding `--max-size` are skipped.
- **Technology detection** – Version identification depends on known technology patterns and supported formats.

---

## License

This project is licensed under the MIT License.

See the `LICENSE` file for details.

---

## Disclaimer

SenseScan is intended for security auditing, defensive analysis, and authorized security research. It is designed to identify potentially exposed sensitive information in files and documents.

The scanner does not verify whether discovered credentials are valid or whether identified endpoints are accessible. Findings should be manually reviewed before being treated as confirmed exposures.
