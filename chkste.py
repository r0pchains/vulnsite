import requests
import random
import time
from stem import Signal
from stem.control import Controller

# List of User-Agent strings to randomize
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36',
]

def check_tor():
    try:
        with Controller.from_port(port=9151) as controller:
            controller.authenticate()
            print("[ INFO ] Tor is running.")
            return True
    except Exception as e:
        print("[ ERROR ] Tor is not running:", e)
        return False

def get_ip():
    response = requests.get("http://httpbin.org/ip", proxies={"http": "socks5h://localhost:9050", "https": "socks5h://localhost:9050"}, timeout=10)
    return response.json().get("origin")

def log_vulnerability(url, vulnerabilities):
    with open('vuln.txt', 'a') as f:
        f.write(f"{url}: {', '.join(vulnerabilities)}\n")
    print(f"[ INFO ] Logged vulnerabilities for {url}.")

def make_request(url):
    """Send a request using Tor."""
    try:
        response = requests.get(url, proxies={"http": "socks5h://localhost:9050", "https": "socks5h://localhost:9050"}, timeout=10)
        return response
    except requests.exceptions.Timeout:
        print(f"[ ERROR ] Request to {url} timed out.")
        exit(1)  # Exit after a timeout
    except requests.exceptions.RequestException as e:
        print(f"[ ERROR ] Error occurred while requesting {url}: {e}")
        exit(1)  # Exit on any other request error
    return None

def discover_robots(url):
    """Check for robots.txt."""
    robots_url = url.rstrip('/') + '/robots.txt'
    response = make_request(robots_url)
    if response:
        if response.status_code == 200:
            print(f"[ INFO ] Found robots.txt: {robots_url}")
            print(response.text)
        else:
            print(f"[ INFO ] robots.txt exists but returned status code {response.status_code}")
    else:
        print("[ INFO ] No robots.txt found.")

def check_cors(url):
    """Check CORS headers."""
    user_agent = random.choice(user_agents)
    headers = {
        'User-Agent': user_agent,
        'Origin': 'http://somesite.com'  # Simulating an unauthorized origin
    }
    vulnerabilities = []
    response = make_request(url)
    if response:
        if 'Access-Control-Allow-Origin' in response.headers:
            allow_origin = response.headers['Access-Control-Allow-Origin']
            print(f"[ INFO ] CORS Header: {allow_origin}")
            if allow_origin == '*':
                vulnerabilities.append("CORS misconfiguration (allows any origin)")
                print("[ VULN ] CORS misconfiguration")
            elif allow_origin == 'http://somesite.com':
                print("[ INFO ] CORS allowed for the simulated origin.")
            else:
                print("[ INFO ] CORS restricted to specific origins.")
        else:
            vulnerabilities.append("No CORS header found")
            print("[ VULN ] No CORS header found, requests from other origins will be blocked.")
    return vulnerabilities, response.headers if response else {}

def check_clickjacking(url):
    """Check X-Frame-Options header for clickjacking vulnerabilities."""
    vulnerabilities = []
    response = make_request(url)
    if response:
        x_frame_options = response.headers.get('X-Frame-Options')
        if x_frame_options:
            print(f"[ INFO ] X-Frame-Options: {x_frame_options}")
            if x_frame_options.lower() not in ['deny', 'sameorigin']:
                vulnerabilities.append("Potentially vulnerable to clickjacking")
                print("[ VULN ] CLICKJACKING")
        else:
            vulnerabilities.append("No X-Frame-Options set")
            print("[ VULN ] No X-Frame-Options set")
    return vulnerabilities, response.headers if response else {}

def check_xss(url):
    """Check for possible XSS vulnerabilities."""
    vulnerabilities = []
    response = make_request(url)
    if response:
        content_type = response.headers.get('Content-Type', '')
        x_xss_protection = response.headers.get('X-XSS-Protection', '')
        
        if 'text/html' in content_type:
            if '1; mode=block' in x_xss_protection:
                print("[ INFO ] X-XSS-Protection is enabled; XSS risk check skipped.")
            elif '<script>' in response.text or 'javascript:' in response.text:
                vulnerabilities.append("Possible XSS risk (contains script tags or JavaScript)")
                print("[ VULN ] XSS risk")
            else:
                vulnerabilities.append("HTML content returned, potential XSS risk needs verification.")
                print("[ VULN ] Potential XSS risk (requires manual verification)")
        else:
            print("[ INFO ] Not HTML content; XSS check skipped.")
    return vulnerabilities, response.headers if response else {}

def check_cache_poisoning(url):
    """Check Cache-Control header for cache poisoning vulnerabilities."""
    user_agent = random.choice(user_agents)
    headers = {
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
    }
    
    vulnerabilities = []
    response = make_request(url)
    if response:
        cache_control = response.headers.get('Cache-Control')
        print(f"[ INFO ] Cache-Control: {cache_control}")

        if cache_control:
            if ("no-cache" in cache_control.lower() or 
                "no-store" in cache_control.lower() or 
                "must-revalidate" in cache_control.lower()):
                vulnerabilities.append("Potentially vulnerable to cache poisoning")
                print("[ VULN ] Cache poisoning risk")
        else:
            vulnerabilities.append("No Cache-Control header found")
            print("[ VULN ] No Cache-Control header found")
    return vulnerabilities, response.headers if response else {}

def fetch_data_from_endpoint(base_url, endpoint):
    """Fetch data from a user-specified endpoint using Tor."""
    full_url = base_url.rstrip('/') + endpoint
    try:
        response = make_request(full_url)
        if response:
            print(f"[ INFO ] Data retrieved from {full_url}")
            # For preview, print the first 1000 characters of the response
            print(response.text[:1000])
            show_headers = input("Would you like to see the full HTTP headers? (y/n): ").strip().lower()
            if show_headers == 'y':
                print("[ INFO ] Headers received:")
                for header, value in response.headers.items():
                    print(f"{header}: {value}")
        else:
            print(f"[ ERROR ] Failed to retrieve data from {full_url}")
    except Exception as e:
        print(f"[ ERROR ] Error fetching data from endpoint: {e}")

# Main logic for handling user input
if __name__ == "__main__":
    if check_tor():
        tor_ip = get_ip()
        print("[ INFO ] Our IP:", tor_ip)
        
        user_input = input("Enter the base URL (e.g., http://example.com):  ")

        while True:
            print("\nWhat would you like to do?")
            print("1. Check for CORS, Clickjacking, XSS, Cache Poisoning headers")
            print("2. Find robots.txt")
            print("3. Fetch data from an endpoint (e.g., /wp-admin/admin-ajax.php)")
            print("4. Quit")

            choice = input("Enter your choice (1-4): ").strip()
            
            if choice == '1':
                all_vulnerabilities = []
                all_headers = {}

                vulnerabilities, headers = check_cors(user_input)
                all_vulnerabilities.extend(vulnerabilities)
                all_headers.update(headers)

                vulnerabilities, headers = check_clickjacking(user_input)
                all_vulnerabilities.extend(vulnerabilities)
                all_headers.update(headers)

                vulnerabilities, headers = check_xss(user_input)
                all_vulnerabilities.extend(vulnerabilities)
                all_headers.update(headers)

                vulnerabilities, headers = check_cache_poisoning(user_input)
                all_vulnerabilities.extend(vulnerabilities)
                all_headers.update(headers)

                if all_vulnerabilities:
                    log_vulnerability(user_input, all_vulnerabilities)
                else:
                    print(f"[ INFO ] No vulnerabilities found for {user_input}.")

                show_headers = input("Would you like to see the full HTTP headers? (y/n): ").strip().lower()
                if show_headers == 'y':
                    print("[ INFO ] Full headers for", user_input)
                    for header, value in all_headers.items():
                        print(f"{header}: {value}")
                
            elif choice == '2':
                discover_robots(user_input)
            elif choice == '3':
                endpoint = input("Enter endpoint to scan (e.g., /admin, /login): ").strip()
                fetch_data_from_endpoint(user_input, endpoint)
            elif choice == '4':
                print("[ INFO ] Exiting...")
                break
            else:
                print("[ ERROR ] Invalid choice. Please try again.")
