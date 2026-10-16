#!/bin/sh
# Builds a .deb from the current tree, on the machine it runs on: the
# dependencies are computed by dpkg-shlibdeps against the libraries
# installed here, so build on the oldest target distro of each family.
# Usage: tools/build-deb.sh [OUTDIR]   (needs build-essential, dpkg-dev,
# pkg-config and the -dev packages of pcre2, netfilter_queue, nftnl, mnl,
# nghttp2, protobuf-c, GTK 2 and sqlite3).
set -eu

cd "$(dirname "$0")/.."
root=$(pwd)
out=${1:-$root/dist}
base=$(sed -n 's/^VERSION *= *//p' config.mk)
upstream=$(sed -n 's/^UPSTREAM_VERSION *= *//p' config.mk)
version=$base+os$upstream
arch=$(dpkg --print-architecture)
maint=${DEB_MAINTAINER:-Kiyoshi Spreclerg <kiyoshi_pip@protonmail.com>}

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pkg=$work/pkg

make clean
make -j"$(nproc)" PREFIX=/usr
make PREFIX=/usr DESTDIR="$pkg" install
strip --strip-unneeded "$pkg/usr/sbin/kisnitchd" "$pkg/usr/bin/kisnitch-gtk"
find "$pkg" -type d -exec chmod 755 {} +

# dpkg-shlibdeps insists on a debian/control in the current directory.
mkdir -p "$work/debian"
printf 'Source: kisnitch\n\nPackage: kisnitch\nArchitecture: any\n' > "$work/debian/control"
(
	cd "$work"
	dpkg-shlibdeps -O -e"$pkg/usr/sbin/kisnitchd" -e"$pkg/usr/bin/kisnitch-gtk" > "$work/substvars"
)
depends=$(sed -n 's/^shlibs:Depends=//p' "$work/substvars")

mkdir -p "$pkg/DEBIAN"
size=$(du -sk "$pkg" | cut -f1)
cat > "$pkg/DEBIAN/control" <<CTL
Package: kisnitch
Version: $version-1
Architecture: $arch
Maintainer: $maint
Installed-Size: $size
Depends: $depends
Conflicts: opensnitch, python3-opensnitch-ui
Section: net
Priority: optional
Homepage: https://github.com/${GITHUB_REPOSITORY:-kisnitch/kisnitch}
Description: interactive application firewall (OpenSnitch port to C and GTK 2)
 Kisnitch is a port of OpenSnitch: a daemon that intercepts outgoing
 connections with nfqueue and nftables, and a GTK 2 interface that asks
 which application may connect where. It speaks OpenSnitch's protocol and
 reads its rules and configuration paths, without systemd.
CTL

deb=$out/kisnitch_${version}-1_${arch}.deb
dpkg-deb --root-owner-group --build "$pkg" "$deb"
echo "$deb"
