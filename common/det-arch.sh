#!/bin/sh

# Detect architecture
arch=""
case $(uname -m) in
    i386)    arch="386" ;;
    i686)    arch="386" ;;
    x86_64)  arch="amd64" ;;
    amd64)   arch="amd64" ;;
    arm64)   arch="arm64" ;;
    aarch64) arch="arm64" ;;
    *)       arch="unknown";;
esac

echo $arch
