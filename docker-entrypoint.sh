#!/bin/sh
# Copy default config files into the data volume on first run.
# Existing files are never overwritten.

if [ ! -f /data/features.json ]; then
    cp /usr/src/app/features.json /data/features.json
fi

if [ ! -f /data/config.json ]; then
    cp /usr/src/app/config.example.json /data/config.json
fi

exec "$@"
