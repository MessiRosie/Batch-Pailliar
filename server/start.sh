#!/bin/bash
# (Re)start the paillier-crypto usage counter.
DIR=/root/paillier-usage
cd "$DIR" || exit 1
if [ -f counter.pid ]; then
    OLD=$(cat counter.pid)
    if kill -0 "$OLD" 2>/dev/null; then
        kill "$OLD" 2>/dev/null
        sleep 1
    fi
fi
nohup python3 counter_server.py >> server.log 2>&1 < /dev/null &
echo $! > counter.pid
sleep 1
echo "started pid $(cat counter.pid)"
