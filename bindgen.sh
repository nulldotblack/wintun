#!/bin/bash

bindgen \
--allowlist-function "Wintun.*" \
--allowlist-type "WINTUN_.*" \
--dynamic-loading wintun \
--dynamic-link-require-all \
wintun/include/wintun_functions.h > src/wintun_raw.rs \
-- --target=i686-pc-windows-msvc

dll_files=(
    wintun/bin/amd64/wintun.dll
    wintun/bin/arm/wintun.dll
    wintun/bin/arm64/wintun.dll
    wintun/bin/x86/wintun.dll
)

function hash_files() {
    local files=("$@")
    local output_file="src/dll_hashes.rs"

    # Start writing the function definition to the output file
    echo "pub fn wintun_dll_hash_sha256() -> std::collections::HashMap<&'static str, &'static str> {" > $output_file
    echo "    [" >> $output_file

    for file in "${files[@]}"; do
        local hash=$(certutil -hashfile $file SHA256 | awk 'FNR == 2 {print $1}')
        # Write the tuple to the output file
        echo "        (" >> $output_file
        echo "            \"$file\"," >> $output_file
        echo "            \"$hash\"," >> $output_file
        echo "        )," >> $output_file
    done

    # Finish writing the function definition to the output file
    echo "    ]" >> $output_file
    echo "    .into_iter()" >> $output_file
    echo "    .collect()" >> $output_file
    echo "}" >> $output_file
}

hash_files "${dll_files[@]}"
