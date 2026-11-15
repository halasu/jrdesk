#!/usr/bin/env bash
# JRDesk branding patch for rustdesk/rustdesk (tested against commit 7949eca, 2026-11-15)
# Usage: run from repo root AFTER `git submodule update --init`
#   JRDESK_ICON_DIR=<dir with jrdesk.ico, icon-{32,64,128,256,512}.png> bash jrdesk-branding.sh
# Scope (v1): server/key embed, display name, icons. Binary/internal names stay "rustdesk"
# so the upstream build scripts keep working.
set -euo pipefail

SERVER="${JRDESK_SERVER:-rd.jrdesk.cloud}"
PUBKEY="${JRDESK_PUBKEY:-TnAmsr8vZbsw+XNlfvx2yxgmMvksYN4tcpipY7GLaJs=}"
NAME="${JRDESK_NAME:-JRDesk}"
ICON_DIR="${JRDESK_ICON_DIR:-res/jrdesk/out}"

# 0) Generate icons (Pillow) unless a prebuilt icon dir was given
if [ ! -f "$ICON_DIR/jrdesk.ico" ] && [ -f res/jrdesk/make_icons.py ]; then
  python -m pip install --quiet pillow || python3 -m pip install --quiet pillow
  (python res/jrdesk/make_icons.py "$ICON_DIR" || python3 res/jrdesk/make_icons.py "$ICON_DIR")
fi

CFG=libs/hbb_common/src/config.rs
test -f "$CFG" || { echo "missing $CFG (init submodules first)"; exit 1; }

# 1) Embedded server + public key + app name
sed -i -E "s|^pub const RENDEZVOUS_SERVERS: &\[&str\] = &\[[^]]*\];|pub const RENDEZVOUS_SERVERS: \&[\&str] = \&[\"${SERVER}\"];|" "$CFG"
sed -i -E "s|^pub const RS_PUB_KEY: &str = \"[^\"]*\";|pub const RS_PUB_KEY: \&str = \"${PUBKEY}\";|" "$CFG"
sed -i -E "s|RwLock::new\(\"RustDesk\".to_owned\(\)\)|RwLock::new(\"${NAME}\".to_owned())|" "$CFG"

# 2) Windows version resource / window title (display only)
RC=flutter/windows/runner/Runner.rc
sed -i -E "s|\"FileDescription\", \"RustDesk Remote Desktop\"|\"FileDescription\", \"${NAME} Remote Desktop\"|; s|\"ProductName\", \"RustDesk\"|\"ProductName\", \"${NAME}\"|" "$RC"
sed -i -E "s|std::wstring app_name = L\"RustDesk\";|std::wstring app_name = L\"${NAME}\";|" flutter/windows/runner/main.cpp
sed -i -E "s|^ProductName = \"RustDesk\"|ProductName = \"${NAME}\"|; s|^FileDescription = \"RustDesk Remote Desktop\"|FileDescription = \"${NAME} Remote Desktop\"|" Cargo.toml

# 3) Icons
if [ -d "$ICON_DIR" ]; then
  cp "$ICON_DIR/jrdesk.ico" res/icon.ico
  cp "$ICON_DIR/jrdesk.ico" flutter/windows/runner/resources/app_icon.ico
  cp "$ICON_DIR/icon-512.png" res/icon.png
  for s in 32 64 128; do cp "$ICON_DIR/icon-$s.png" "res/${s}x${s}.png"; done
  cp "$ICON_DIR/icon-256.png" res/128x128@2x.png
else
  echo "WARN: icon dir $ICON_DIR not found, icons unchanged"
fi

echo "== verify =="
grep -n "RENDEZVOUS_SERVERS\|RS_PUB_KEY\|RwLock::new(\"${NAME}\"" "$CFG"
grep -n "ProductName\|FileDescription" "$RC" Cargo.toml
