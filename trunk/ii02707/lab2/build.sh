#!/bin/bash

echo "Start Configuring..."
cmake -S ./src -B ./build
echo "Configuring has been ended!"

echo "Start Building..."
cmake --build ./build
echo "Building has been ended!"