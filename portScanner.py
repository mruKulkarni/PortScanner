import requests
import ssl
import threading
from OpenSSL import SSL
import socket
# from zapv2 import ZAPv2
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Define the target URL to be assessed
target_url = "https://online.canarabank.in" # a safer website 
# try with https://example.com less safer website

try:
    # Disable SSL certificate verification (for demonstration purposes only, not recommended for production use)
    ssl._create_default_https_context = ssl._create_unverified_context

    # Send a HEAD request to the target URL to retrieve headers
    response = requests.head(target_url)

    # Check the response status code
    if response.status_code == 200:
        print(f"Target URL {target_url} is accessible (status code: {response.status_code}).")
        # Check if SSL certificate is valid
        if response.headers.get('Strict-Transport-Security'):
            print("Strict Transport Security (HSTS) header is present.")
        if response.headers.get('X-Content-Type-Options'):
            print("X-Content-Type-Options header is present.")
        if response.headers.get('X-XSS-Protection'):
            print("X-XSS-Protection header is present.")
        if response.headers.get('X-Frame-Options'):
            print("X-Frame-Options header is present.")
        # Perform further security checks or vulnerability scans here
    else:
        print(f"Target URL {target_url} is not accessible (status code: {response.status_code}).")
except requests.exceptions.RequestException as e:
    print(f"Error occurred while making the request: {e}")


def check_ssl_tls_configuration(website_url):
    """
    Check SSL/TLS configuration for a given website.
    """
    try:
        # Create a socket
        sock = socket.create_connection((website_url, 443))

        # Wrap the socket with SSL
        ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv23)

        # Get the SSL/TLS configuration information
        cipher = ssl_sock.cipher()
        print("Website URL:", website_url)
        print("Protocol Version:", ssl_sock.version())
        print("Cipher Suite:", cipher[0])
        print("SSL/TLS Configuration is secure.")
        
    except ssl.SSLError as e:
        print("Website URL:", website_url)
        print("Error:", e)
    except Exception as e:
        print("Error:", e)
    finally:
        # Close the SSL socket
        ssl_sock.close()
        sock.close()

# Example usage
website_url = "example.com"
check_ssl_tls_configuration(website_url)
website_url = 'www.example.com'

# Establish an SSL/TLS connection to the website
context = ssl.create_default_context()
sock = socket.create_connection((website_url, 443))
ssl_sock = context.wrap_socket(sock, server_hostname=website_url)

# Get the SSL/TLS certificate from the website
certificate = ssl_sock.getpeercert(binary_form=True)
ssl_sock.close()

# Parse the certificate using cryptography
cert = x509.load_der_x509_certificate(certificate, default_backend())

# Extract certificate information
subject = cert.subject
issuer = cert.issuer
serial_number = cert.serial_number
not_valid_before = cert.not_valid_before
not_valid_after = cert.not_valid_after

# Print the extracted certificate information
print(f'Subject: {subject}')
print(f'Issuer: {issuer}')
print(f'Serial Number: {serial_number}')
print(f'Not Valid Before: {not_valid_before}')
print(f'Not Valid After: {not_valid_after}')
url = 'https://example.com/'

# Define a list of payloads for SQL injection testing
sql_injection_payloads = ["' OR '1'='1", "'; DROP TABLE users;", "SELECT * FROM users WHERE username = 'admin' AND password = 'password'"]

# Define a list of payloads for XSS testing
xss_payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(\'XSS\')">']

# Define headers for the HTTP request
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}

# Test for SQL injection vulnerabilities
for payload in sql_injection_payloads:
    payload_url = url + payload
    response = requests.get(payload_url, headers=headers)
    if "error" in response.text:
        print(f"SQL Injection vulnerability found at: {payload_url}")
        break
else:
    print("No SQL Injection vulnerabilities found.")

# Test for XSS vulnerabilities
for payload in xss_payloads:
    payload_url = url + payload
    response = requests.get(payload_url, headers=headers)
    if payload in response.text:
        print(f"XSS vulnerability found at: {payload_url}")
        break
else:
    print("No XSS vulnerabilities found.")


print("THE OPEN PORTS ARE :")
# Define the number of threads for concurrent scanning
NUM_THREADS = 1000

def scan_ports(website, port_range):
    open_ports = []
    try:
        # Convert the website to IP address if needed
        if not website.replace(".", "").isdigit():
            ip = socket.gethostbyname(website)
        else:
            ip = website

        # Define a function for threaded port scanning
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # Set timeout for socket connection
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass

        # Create and start threads for concurrent port scanning
        threads = []
        for port in range(port_range[0], port_range[1] + 1):
            t = threading.Thread(target=scan_port, args=(port,))
            threads.append(t)
            t.start()

        # Wait for all threads to finish
        for t in threads:
            t.join()

        if open_ports:
            print(f"Open ports on website {website}: {open_ports}")
        else:
            print(f"No open ports found on website {website}.")
    except socket.gaierror:
        print(f"Failed to resolve website {website}.")
    except Exception as e:
        print(f"Failed to scan ports on website {website}: {e}")

# Replace "example.com" with the actual website you want to test
website = "example.com"
# Replace the port range with the specific range of ports you want to scan
port_range = (1, 65535)

scan_ports(website, port_range)
