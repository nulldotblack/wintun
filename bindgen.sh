#!/bin/bash
bindgen --dynamic-loading wintun wintun/wintun-wrapper.h > src/wintun_raw.rs
