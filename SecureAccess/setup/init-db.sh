#!/bin/bash

echo "Initializing database..."


echo "Initialising postgres..."

sudo apt update
sudo apt install postgresql postgresql-client

sudo systemctl start postgresql
sudo systemctl enable postgresql

sudo cp ../SIRS.sql /var/lib/postgresql/
sudo chown postgres:postgres /var/lib/postgresql/SIRS.sql
sudo chmod +x /var/lib/postgresql/SIRS.sql

sudo cp postgres/postgresql.conf /etc/postgresql/17/main/postgresql.conf
sudo cp postgres/pg_hba.conf /etc/postgresql/17/main/pg_hba.conf

sudo systemctl restart postgresql


echo "Setting network configuration..."

sudo cp network/db /etc/network/interfaces

sudo systemctl restart NetworkManager
