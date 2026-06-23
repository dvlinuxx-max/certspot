# certspot

Enumerate a domain's subdomains from public Certificate Transparency logs.
Every publicly trusted TLS certificate is logged to CT; certspot queries
[crt.sh](https://crt.sh) for certificates issued to a domain and extracts the
unique hostnames. Passive OSINT — no traffic is sent to the target itself.

Use it on domains you own or are authorized to assess.

## Usage

```bash
python certspot.py example.com
python certspot.py example.com --json
```

## Example

```
$ python certspot.py hackerone.com

certspot hackerone.com  15 unique hostnames

  api.hackerone.com
  docs.hackerone.com
  events.hackerone.com
  ...
```

## How it works

```
certspot.py
  query_crtsh    GET crt.sh JSON (retries on 502/503/504 — crt.sh is flaky)
  extract_hosts  pull name_value/common_name, strip wildcards, dedupe,
                 keep only names under the target apex
```

crt.sh is a free community service and is frequently overloaded; certspot
retries a few times with backoff before giving up.

## Requirements

Python 3.9+, network access. No third-party packages.

## License

MIT
