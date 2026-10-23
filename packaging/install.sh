#!/bin/sh
set -eu
# The destination is the root of a dedicated emptyDir, mounted only for this plugin.
cd /artifact
sha256sum -c /manifest.sha256 >/dev/null
cp -R /artifact/. /destination/
cd /destination
sha256sum -c /manifest.sha256 >/dev/null
