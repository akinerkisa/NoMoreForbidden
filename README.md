# NoMoreForbidden

NoMoreForbidden is a tool that tries various techniques to bypass forbidden(403) pages on websites and presents their results to the user.

> [!NOTE]
> NoMoreForbidden now has golang version. Check in https://github.com/akinerkisa/GoNMF

> [!NOTE]
> You can try this tool with https://github.com/akinerkisa/renikApp 403 vulnerable page section.

## Installation
<code>git clone https://github.com/akinerkisa/NoMoreForbidden</code>
<p><code>cd NoMoreForbidden</code></p>
<p><code>pip install -r requirements.txt</code></p>
  
## Usage
<code>python3 nmf.py -u https://www.example.com/test </code>

Flag | Description | Example | Default |
--- | --- | --- | --- |
-u | Specify URL | python3 nmf.py -u https://www.example.com/test | N/A |
-ip | Specify ip adress for ip-based headers | python3 nmf.py -ip 1.1.1.1 | 127.0.0.1 |
-v | Toggles showing all Valid/Invalid results | python3 nmf.py -v on/off | off |

## Features
<li> Url based bypass ( url.com/path/../ etc.)
<li>Ip-based header bypass ( X-Forwarded-For etc.)
<li> Web cache based header bypass ( X-Original-URL etc.)
<li> Path char change based bypass (admin to aDmIn)
<li> Protocol change based bypass (http to https - https to http)
<li> Wayback Machine history check
<li> False-Positive result detection</li>
<li> Ip Adress based bypass  -new v0.2 </li>
<li> HTTP Protocol version based bypass  -new v0.2 </li>

## How to work False-Positive Detection
<code>https://google.com/test/../ etc.</code> payloads or <code>X-Original-URL etc.</code> headers such as has a high false-positive rate. NoMoreForbidden is compares main page response length and bypass result response length. If them is equal, at high rate this result is false-positive. However, this system cannot always be trusted. On some websites (eg google.com) page lengths vary and this prevents the program from detecting false-positive.

## How to work CDN/WAF && Cloudflare - Cloudfront Detection
IP address-based bypass only works with the origin IP. If the target uses services like Cloudflare or CloudFront, we cannot access the original IP. While testing IP address bypass, NMF checks the server, and if the website uses Cloudflare or CloudFront, NMF notifies the user of this. Additionally, SSL Handshake failed error may also indicate a cdn/waf. This is also notified to the user.

## References
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses
