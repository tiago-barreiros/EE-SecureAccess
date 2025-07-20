#!/bin/bash

echo "Initializing API..."


echo "Setting network configuration..."

sudo cp network/api /etc/network/interfaces

sudo systemctl restart NetworkManager