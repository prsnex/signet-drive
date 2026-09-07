#!/usr/bin/env bash
# bug099: generate cli/assets/AppIcon.icns for the Signet app bundle from the
# canonical brand seal (the web favicon — purple #3f3d8a seal on warm paper). The
# BUILD copies the committed .icns (byte-reproducible); this script is provenance +
# a one-command regenerate if the seal ever changes. Requires rsvg-convert + iconutil.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRC="$REPO/web/static/favicon.svg"
OUT="$REPO/cli/assets/AppIcon.icns"
TMP="$(mktemp -d)/AppIcon.iconset"; mkdir -p "$TMP"
for pair in "16 icon_16x16" "32 icon_16x16@2x" "32 icon_32x32" "64 icon_32x32@2x" \
            "128 icon_128x128" "256 icon_128x128@2x" "256 icon_256x256" \
            "512 icon_256x256@2x" "512 icon_512x512" "1024 icon_512x512@2x"; do
  set -- $pair
  rsvg-convert -w "$1" -h "$1" "$SRC" -o "$TMP/$2.png"
done
iconutil -c icns "$TMP" -o "$OUT"
echo "wrote $OUT ($(du -h "$OUT" | awk '{print $1}'))"
