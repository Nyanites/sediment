#!/bin/bash
# Builds a universal (Apple Silicon + Intel) Sediment.app and zips it to
# target/Sediment-macos.zip. Run on macOS with both Rust targets installed:
#
#   rustup target add aarch64-apple-darwin x86_64-apple-darwin
#   scripts/bundle-macos.sh
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
export MACOSX_DEPLOYMENT_TARGET=11.0

for t in aarch64-apple-darwin x86_64-apple-darwin; do
    cargo build --release --locked --target "$t"
done

app=target/Sediment.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
lipo -create -output "$app/Contents/MacOS/sediment" \
    target/aarch64-apple-darwin/release/sediment \
    target/x86_64-apple-darwin/release/sediment

iconset=target/Sediment.iconset
rm -rf "$iconset"
mkdir -p "$iconset"
for s in 16 32 64 128 256; do
    sips -z $s $s assets/icon.png --out "$iconset/icon_${s}x${s}.png" >/dev/null
done
for s in 16 32 64 128; do
    cp "$iconset/icon_$((s * 2))x$((s * 2)).png" "$iconset/icon_${s}x${s}@2x.png"
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key><string>Sediment</string>
    <key>CFBundleDisplayName</key><string>Sediment</string>
    <key>CFBundleIdentifier</key><string>io.github.nyanites.sediment</string>
    <key>CFBundleExecutable</key><string>sediment</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>$version</string>
    <key>CFBundleVersion</key><string>$version</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

# Ad-hoc signature with the hardened runtime: required to run on Apple Silicon.
codesign --force --options runtime --sign - "$app"
codesign --verify --strict "$app"

rm -f target/Sediment-macos.zip
ditto -c -k --keepParent "$app" target/Sediment-macos.zip
echo "target/Sediment-macos.zip"
