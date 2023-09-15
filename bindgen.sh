#!/bin/bash
bindgen \
--allowlist-function "Wintun.*" \
--allowlist-type "WINTUN_.*" \
--dynamic-loading wintun \
--dynamic-link-require-all \
wintun/include/wintun_functions.h > src/wintun_raw.rs \
-- --target=i686-pc-windows-msvc