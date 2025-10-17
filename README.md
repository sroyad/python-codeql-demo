# Python CodeQL Demo Repository

This repository contains a vulnerable Python Flask application designed to demonstrate CodeQL security scanning capabilities.

## Vulnerabilities Included

This application intentionally contains the following security vulnerabilities for testing purposes:

1. **SQL Injection** - `/user` endpoint
2. **Command Injection** - `/ping` endpoint  
3. **Path Traversal** - `/file` endpoint
4. **Cross-Site Scripting (XSS)** - `/search` endpoint
5. **Hardcoded Credentials** - `/admin` endpoint
6. **Insecure Deserialization** - `/data` endpoint
7. **Weak Cryptography** - `/encrypt` endpoint (MD5)
8. **File Upload Vulnerability** - `/upload` endpoint

## Running the Application

```bash
pip install -r requirements.txt
python app.py
```

The application will be available at `http://localhost:5000`

## CodeQL Testing

This repository is configured with two CodeQL workflows:

- **Baseline CodeQL** - Uses default CodeQL configuration
- **Optimized CodeQL** - Uses custom configuration with `security-extended` queries

## Security Notice

⚠️ **WARNING**: This application contains intentional security vulnerabilities and should NEVER be used in production environments.
