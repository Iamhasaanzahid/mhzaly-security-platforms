# MHZALY Enterprise Security Platform v3.0
## Architecture & Implementation Documentation

---

## 📋 Table of Contents

1. [System Architecture](#system-architecture)
2. [Core Components](#core-components)
3. [API Integration Layer](#api-integration-layer)
4. [Red Team Module](#red-team-module)
5. [Blue Team Module](#blue-team-module)
6. [AI Analysis Engine](#ai-analysis-engine)
7. [Reporting System](#reporting-system)
8. [Database Design](#database-design)
9. [Deployment Guide](#deployment-guide)
10. [Production Checklist](#production-checklist)

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         MHZALY PLATFORM                              │
├─────────────────────────────────────────────────────────────────────┤
│                        Streamlit UI Layer                             │
├─────────────────────────────────────────────────────────────────────┤
│  Dashboard │ Red Team │ Blue Team │ AI Analysis │ Reports │ Settings │
├─────────────────────────────────────────────────────────────────────┤
│                    Business Logic Layer                               │
├───────────────────┬──────────────────┬──────────────────┬────────────┤
│   Red Team Ops    │  Blue Team Ops   │  AI Analyzer     │  Reports   │
│  ┌─────────────┐  │  ┌────────────┐  │  ┌────────────┐  │  ┌──────┐  │
│  │Recon        │  │  │Monitoring  │  │  │Vuln        │  │  │JSON  │  │
│  │Scanning     │  │  │Threat Hunt │  │  │Analysis    │  │  │PDF   │  │
│  │Vuln Research│  │  │Incident IR │  │  │Remediation │  │  │MD    │  │
│  └─────────────┘  │  └────────────┘  │  └────────────┘  │  └──────┘  │
├───────────────────┴──────────────────┴──────────────────┴────────────┤
│                    API Orchestration Layer                             │
├──────────────────┬──────────────────┬──────────────────┬─────────────┤
│   NVD API        │  VirusTotal API  │  AbuseIPDB API   │  CISA API   │
│  ┌────────────┐  │  ┌────────────┐  │  ┌────────────┐  │  ┌──────────┐│
│  │Rate Limit  │  │  │Rate Limit  │  │  │Rate Limit  │  │  │Public    ││
│  │Retry Logic │  │  │Retry Logic │  │  │Retry Logic │  │  │Database  ││
│  │Cache       │  │  │Cache       │  │  │Cache       │  │  │          ││
│  │Fallback    │  │  │Fallback    │  │  │Fallback    │  │  │          ││
│  └────────────┘  │  └────────────┘  │  └────────────┘  │  └──────────┘│
├──────────────────┴──────────────────┴──────────────────┴─────────────┤
│                    Infrastructure Layer                                │
├──────────────────┬──────────────────┬──────────────────────────────────┤
│   SQLite DB      │   File Cache     │   Session Management             │
│   Logging        │   Error Handling │   Rate Limiting                  │
└──────────────────┴──────────────────┴──────────────────────────────────┘
```

---

## Core Components

### 1. RateLimiter (Token Bucket Algorithm)
- **Purpose:** Manage API rate limits across multiple sources
- **Implementation:** Thread-safe token bucket with sliding window
- **Features:**
  - Configurable requests per second
  - Automatic backoff on rate limit
  - Multi-threaded safety

```python
# Example usage
limiter = RateLimiter(requests_per_second=2.0)
limiter.acquire()  # Wait until ready
response = api.request()
```

### 2. APIResponse (Response Wrapper)
- **Purpose:** Standardize responses from all APIs
- **Fields:**
  - `data`: API response data
  - `status`: HTTP status code
  - `error`: Error message if any
  - `source`: Which API provided response
  - `timestamp`: Response timestamp
  - `success`: Boolean success indicator

### 3. SecurityAPIBase (Abstract Base Class)
- **Purpose:** Define common interface for all security APIs
- **Key Methods:**
  - `check_indicator()`: Check threat indicators
  - `get_vulnerability()`: Retrieve vulnerability info
  - `_make_request()`: Robust HTTP request handling

---

## API Integration Layer

### NVD (National Vulnerability Database)
**Authentication:** Public access
**Rate Limit:** 5 requests per 30 seconds
**Features:**
- CVE search and retrieval
- Product-based vulnerability search
- Comprehensive CVSS scoring

**Key Methods:**
```python
nvd.get_vulnerability('CVE-2024-12345')
nvd.search_by_keyword('wordpress', max_results=10)
nvd.get_by_product('nginx')
```

### VirusTotal API
**Authentication:** API key required
**Rate Limit:** 500 requests/day (free tier)
**Features:**
- Multi-indicator checking (IP, domain, hash, URL)
- Detailed malware detection
- File and URL reputation

**Key Methods:**
```python
vt.check_indicator('192.168.1.1')
vt.check_indicator('malware.com')
vt.check_indicator('a1b2c3d4...')  # File hash
```

### AbuseIPDB API
**Authentication:** API key required
**Rate Limit:** 1000 requests/day (free tier)
**Features:**
- IP reputation scoring
- Abuse confidence score
- Bulk IP checking

**Key Methods:**
```python
abuseipdb.check_indicator('192.168.1.1')
abuseipdb.bulk_check(['192.168.1.1', '10.0.0.1'])
```

### CISA KEV Database
**Authentication:** Public access
**Features:**
- Known Exploited Vulnerabilities
- Active exploitation tracking
- Vendor advisories

**Key Methods:**
```python
cisa.get_vulnerability('CVE-2024-12345')
cisa.get_exploited_vulnerabilities(product='wordpress')
```

### APIOrchestrator (Master Controller)
**Purpose:** Coordinate multiple APIs with intelligent fallback
**Features:**
- Query all relevant APIs automatically
- Correlate results across sources
- Intelligent caching (1-hour TTL)
- Graceful error handling

**Example:**
```python
orchestrator = APIOrchestrator(api_keys)

# Check threat indicator across all sources
threat_data = orchestrator.check_threat_indicator('malicious.com')

# Research CVE across all sources
cve_data = orchestrator.research_cve('CVE-2024-12345')
```

---

## Red Team Module

### RedTeamScanner Class

#### 1. DNS Reconnaissance
**Method:** `dns_reconnaissance(domain: str)`
- Queries: A, AAAA, MX, TXT, NS, CNAME, SOA, SRV
- Returns: Dictionary with record types and values
- Identifies mail servers, nameservers, DNS records

#### 2. Subdomain Enumeration
**Method:** `subdomain_enumeration(domain: str, wordlist: Optional[List[str]])`
- Brute-forces 40+ common subdomain prefixes
- DNS-based (no network scanning)
- Discovers hidden infrastructure

#### 3. Port Scanning
**Method:** `port_scanning(host: str, ports: Optional[List[int]])`
- Scans 30+ common service ports
- Identifies open ports and services
- Assesses port risk level

#### 4. SSL/TLS Analysis
**Method:** `ssl_tls_analysis(host: str)`
- Validates certificate
- Checks expiration
- Parses subject and issuer
- Identifies vulnerabilities

#### 5. Technology Detection
**Method:** `web_technology_detection(url: str)`
- Detects: Web servers, CMS, Frameworks, CDN, Analytics
- Pattern matching on HTTP responses
- Header-based detection

#### 6. Vulnerability Scanning
**Method:** `vulnerability_scanning(url: str, api_orchestrator)`
- Correlates detected tech with CVE databases
- Returns prioritized vulnerability list
- Integrates with API orchestrator

---

## Blue Team Module

### BlueTeamDefense Class

#### 1. Security Headers Analysis
**Method:** `analyze_security_headers(url: str)`
**Headers Checked:**
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- Content-Security-Policy (CSP)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy

#### 2. SIEM Rules
**Pre-loaded Detection Rules:**
- Multiple Failed Login Attempts
- Lateral Movement Detection
- Data Exfiltration Attempts
- Privilege Escalation

#### 3. Threat Hunting
**Method:** `threat_hunting_query(logs, pattern)`
- Pattern matching in log data
- Identifies potential threats
- Returns matching log entries

#### 4. Anomaly Detection
**Method:** `anomaly_detection(metrics)`
- Statistical analysis (mean + std dev)
- Detects outliers (>2σ)
- Classifies anomaly severity

#### 5. Incident Triage
**Method:** `incident_triage(alert)`
- Prioritizes incidents
- Assigns IR playbook
- Determines escalation path

---

## AI Analysis Engine

### AIVulnerabilityAnalyzer Class

#### Features:

1. **Vulnerability Analysis**
   - Deep dive into CVE details
   - Root cause analysis
   - Attack vector explanation
   - Remediation steps
   - Business impact assessment

2. **Code Security Analysis**
   - Source code vulnerability scanning
   - Pattern-based detection
   - Security anti-patterns identification
   - Secure alternatives suggestion

3. **Remediation Patch Generation**
   - Contextual code patches
   - Industry best practices
   - Secure coding examples

#### Implementation:
- **Primary:** Google Gemini API (claude-3-sonnet-20240229)
- **Fallback:** Rule-based analysis if AI unavailable
- **Confidence Scoring:** 0.0-1.0 scale

```python
analyzer = AIVulnerabilityAnalyzer(gemini_api_key)

# Analyze vulnerability
analysis = analyzer.analyze_vulnerability(vulnerability_obj)

# Analyze source code
code_analysis = analyzer.analyze_code_security(code_snippet)

# Generate patches
patches = analyzer.generate_remediation_patches(vulnerability_obj)
```

---

## Reporting System

### EnterpriseReportGenerator

#### Report Formats:

1. **JSON Report**
   - Machine-readable format
   - Complete metadata
   - Programmatic processing
   - Integration-ready

2. **Markdown Report**
   - Human-readable format
   - Professional formatting
   - Easy GitHub integration
   - Version control friendly

3. **PDF Report** (via ReportLab)
   - Executive summary
   - Detailed findings
   - Risk metrics
   - Professional branding

#### Report Contents:
- Executive summary
- Vulnerability findings (grouped by severity)
- Risk scoring
- Remediation roadmap
- Compliance mapping
- Timeline and methodology

---

## Database Design

### Schema

```sql
-- Scans Table
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    asset TEXT,
    scan_type TEXT,
    status TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    findings_count INTEGER,
    metadata TEXT
);

-- Vulnerabilities Table
CREATE TABLE vulnerabilities (
    vuln_id INTEGER PRIMARY KEY,
    cve_id TEXT UNIQUE,
    title TEXT,
    description TEXT,
    severity TEXT,
    cvss_score REAL,
    affected_products TEXT,
    status TEXT,
    discovered_at TIMESTAMP,
    remediated_at TIMESTAMP
);

-- Incidents Table
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT,
    severity TEXT,
    affected_assets TEXT,
    status TEXT,
    created_at TIMESTAMP,
    closed_at TIMESTAMP,
    root_cause TEXT
);
```

---

## Deployment Guide

### Prerequisites
- Python 3.9+
- pip or poetry
- Git
- API keys (VirusTotal, AbuseIPDB, Gemini)

### Local Development

```bash
# 1. Clone repository
git clone <repo-url>
cd mhzaly-security-platform

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Mac/Linux
# or
venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements_enterprise.txt

# 4. Create .streamlit directory
mkdir -p .streamlit

# 5. Create secrets.toml
cat > .streamlit/secrets.toml << EOF
APP_USERNAME = "admin"
APP_PASSWORD = "your-secure-password"
VIRUSTOTAL_API_KEY = "your-key"
ABUSEIPDB_API_KEY = "your-key"
GEMINI_API_KEY = "your-key"
EOF

# 6. Run locally
streamlit run professional_platform_enterprise.py
```

### Production Deployment (Streamlit Cloud)

```bash
# 1. Push to GitHub
git add .
git commit -m "Deploy MHZALY Enterprise Platform"
git push origin main

# 2. Go to https://streamlit.io/cloud
# 3. Create new app
# 4. Select repository and professional_platform_enterprise.py
# 5. Deploy

# 6. Add secrets on Streamlit Cloud
# Settings → Secrets → Paste secrets.toml content
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements_enterprise.txt .
RUN pip install -r requirements_enterprise.txt

COPY professional_platform_enterprise.py .

EXPOSE 8501

CMD ["streamlit", "run", "professional_platform_enterprise.py", "--server.port=8501"]
```

```bash
# Build
docker build -t mhzaly-platform .

# Run
docker run -p 8501:8501 -e STREAMLIT_SERVER_HEADLESS=true mhzaly-platform
```

---

## Production Checklist

### Security
- [ ] All API keys in environment variables
- [ ] No secrets committed to repository
- [ ] HTTPS/TLS enabled
- [ ] Authentication implemented
- [ ] Rate limiting configured
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention
- [ ] CORS properly configured

### Performance
- [ ] API response caching implemented
- [ ] Database indexes created
- [ ] Query optimization completed
- [ ] Connection pooling enabled
- [ ] Load testing completed
- [ ] Scaling strategy documented

### Monitoring
- [ ] Logging configured
- [ ] Error tracking setup (Sentry)
- [ ] Performance monitoring
- [ ] Uptime monitoring
- [ ] Alert system configured
- [ ] Backup strategy in place

### Documentation
- [ ] README.md complete
- [ ] API documentation
- [ ] Deployment guide
- [ ] Architecture documented
- [ ] Troubleshooting guide
- [ ] User manual

### Testing
- [ ] Unit tests written
- [ ] Integration tests passed
- [ ] Security scan passed
- [ ] Load testing completed
- [ ] User acceptance testing
- [ ] Penetration testing

---

## Performance Metrics

### Expected Performance

- **DNS Enumeration:** 2-5 seconds
- **Subdomain Discovery:** 10-30 seconds
- **Port Scanning:** 15-45 seconds
- **SSL Analysis:** 2-5 seconds
- **Full Vulnerability Scan:** 60-120 seconds
- **CVE Research:** 5-15 seconds per CVE

### Scalability

- **Concurrent Users:** 100+ with caching
- **Vulnerability Database:** Unlimited (API-backed)
- **Report Generation:** <5 seconds
- **API Rate Limits:** Respected and managed

---

## Support & Maintenance

### Regular Maintenance Tasks

1. **Weekly:**
   - Review logs for errors
   - Monitor API usage
   - Update threat intelligence cache

2. **Monthly:**
   - Rotate API keys
   - Review and update rules
   - Audit access logs
   - Update dependencies

3. **Quarterly:**
   - Security assessment
   - Performance review
   - Disaster recovery drill
   - Update documentation

---

*This documentation is current as of MHZALY Platform v3.0*
*Last Updated: September 2024*
