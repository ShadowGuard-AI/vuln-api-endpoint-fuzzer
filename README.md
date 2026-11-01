# vuln-API-Endpoint-Fuzzer
Fuzzes API endpoints with various payloads (including SQL injection, command injection, and XSS) to identify potential vulnerabilities in the API's input validation and data handling. It uses a predefined list of common API endpoints and automatically generates fuzzing payloads. A status code by itself is never reported as a vulnerability; non-2xx responses appear only in an informational status count. Reflection is reported for the payload family actually sent, on any response. Response bodies are logged only as a short excerpt with credential shaped values redacted, and nothing is saved to a file. A run in which no request succeeds ends as failed at a non-zero exit instead of reporting completion. - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuardAI/vuln-api-endpoint-fuzzer`

## Usage
`./vuln-api-endpoint-fuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-e`: Specific endpoints to fuzz (optional, overrides common endpoints)
- `-p`: Specific payload types to use (optional, default is all)
- `-t`: Request timeout in seconds (default: 5)
- `-v`: Enable verbose output (debug logging)

## License
Copyright (c) ShadowGuardAI
