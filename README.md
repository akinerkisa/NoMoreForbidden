# NoMoreForbidden

NoMoreForbidden is a tool that tries various techniques to bypass forbidden(403) pages on websites and presents their results to the user.

## Installation
<code>git clone https://github.com/0akiner/NoMoreForbidden</code>
<p><code>cd NoMoreForbidden</code></p>
<p><code>pip install -r requirements.txt</code></p>
  
## Usage
<code>python3 nmf.py -u https://www.google.com/test </code>

Flag | Description | Example | Default |
--- | --- | --- | --- |
-u | Specify URL | python3 nmf.py -u https://www.google.com/test | N/A |
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

## How to work False-Positive Detection
<code>https://google.com/test/../ etc.</code> payloads or <code>X-Original-URL etc.</code> headers such as has a high false-positive rate. NoMoreForbidden is compares main page response length and bypass result response length. If them is equal, at high rate this result is false-positive. However, this system cannot always be trusted. On some websites (eg google.com) page lengths vary and this prevents the program from detecting false-positive.

