#!/usr/bin/env python3
"""Insert a telemetry route into the LiteLLM nginx vhost (idempotent + reversible).

Adds:  location = /telemetry  ->  proxy_pass http://127.0.0.1:8088
Backs up the config, validates with nginx -t, and reloads only on success.
"""
import shutil
import subprocess
import sys
import time

CONF = "/etc/nginx/sites-enabled/litellm.conf"

BLOCK = """\
    # telemetry endpoint (usage counter)
    location = /telemetry {
        proxy_pass http://127.0.0.1:8088;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

"""

ANCHOR = "    location / {\n        proxy_pass http://127.0.0.1:4000;"

with open(CONF) as f:
    content = f.read()

if "location = /telemetry" in content:
    print("telemetry route already present; nothing to do")
    sys.exit(0)

bak = CONF + ".bak." + time.strftime("%Y%m%d%H%M%S")
shutil.copy2(CONF, bak)
print("backed up to", bak)

idx = content.find(ANCHOR)
if idx < 0:
    print("ERROR: catch-all anchor not found; config may have changed", file=sys.stderr)
    sys.exit(2)

content = content[:idx] + BLOCK + content[idx:]
with open(CONF, "w") as f:
    f.write(content)

r = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
print(r.stdout, end="")
print(r.stderr, end="", file=sys.stderr)
if r.returncode != 0:
    print("nginx -t FAILED; restoring backup", file=sys.stderr)
    shutil.copy2(bak, CONF)
    sys.exit(3)

r2 = subprocess.run(["systemctl", "reload", "nginx"], capture_output=True, text=True)
print("reload rc =", r2.returncode)
if r2.stdout:
    print(r2.stdout, end="")
if r2.stderr:
    print(r2.stderr, end="", file=sys.stderr)
print("DONE")
