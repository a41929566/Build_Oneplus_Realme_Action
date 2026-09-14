#!/system/bin/sh

MODDIR="${0%/*}"
INDEX="$MODDIR/webroot/index.html"

if [ -r "$INDEX" ]; then
    cat "$INDEX"
else
    printf '%s\n' '<!doctype html><html><body><h3>SUSFS Env Guard</h3><p>webroot/index.html is missing.</p></body></html>'
fi
