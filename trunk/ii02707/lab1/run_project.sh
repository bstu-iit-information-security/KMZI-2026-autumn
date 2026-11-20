#!/bin/bash

set -e

BUILD_DIR="./build"
EXECUTABLE="${BUILD_DIR}/belt_gcm"

if [ ! -d "${BUILD_DIR}" ]; then
    echo "Error: build directory '${BUILD_DIR}' does not exist." >&2
    echo "Run cmake/make first." >&2
    exit 1
fi

if [ ! -f "${EXECUTABLE}" ]; then
    echo "Error: executable '${EXECUTABLE}' not found." >&2
    echo "Run cmake/make first." >&2
    exit 1
fi

if [ ! -x "${EXECUTABLE}" ]; then
    echo "Error: '${EXECUTABLE}' is not executable." >&2
    exit 1
fi

"${EXECUTABLE}"