#!/bin/sh
if [ -z "$SKIP_BUILD" ]; then
    cargo build --release --all-features --bin quincy-client-gui --bin quincy-client-daemon
fi
