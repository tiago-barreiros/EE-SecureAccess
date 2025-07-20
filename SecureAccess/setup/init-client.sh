#!/bin/bash

echo "Initializing client..."


echo "Setting network configuration..."

sudo cp network/client /etc/network/interfaces

sudo systemctl restart NetworkManager