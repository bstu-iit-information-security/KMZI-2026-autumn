#!/bin/bash

echo "Starting configuring cli..."
cmake -S ../ -B ../build -DCMAKE_BUILD_TYPE=Release
echo "cli has configured successfuly!"

echo "Starting building cli..."
cmake --build ../build -j
echo "cli has built successfuly!"