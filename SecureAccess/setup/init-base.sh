#!/bin/bash

echo "Initializing base..."


echo "Creating certificates..."

# api certificate
sudo mkdir ../certificates/api
sudo openssl req -new -newkey rsa:4096 -nodes -keyout ../certificates/api/key.pem -out ../certificates/api/cert.csr -config ../certificates/api.cnf
sudo openssl x509 -req -days 365 -in ../certificates/api/cert.csr -signkey ../certificates/api/key.pem -extfile ../certificates/api.cnf -extensions req_ext -out ../certificates/api/cert.pem
sudo openssl pkcs12 -export -in ../certificates/api/cert.pem -inkey ../certificates/api/key.pem -out ../src/main/resources/keystore.p12 -name notist -passout pass:notist
sudo rm -r ../certificates/api

# db certificate
sudo mkdir ../certificates/db
sudo openssl req -new -newkey rsa:4096 -nodes -keyout ../certificates/db/key.pem -out ../certificates/db/cert.csr -config ../certificates/db.cnf
sudo openssl x509 -req -days 365 -in ../certificates/db/cert.csr -signkey ../certificates/db/key.pem -extfile ../certificates/db.cnf -extensions req_ext -out ../certificates/db/cert.pem

sudo cp -r ../certificates/db /etc/postgresql/17/certs
sudo chmod 600 /etc/postgresql/17/certs/cert.pem
sudo chmod 600 /etc/postgresql/17/certs/key.pem
sudo chown postgres:postgres /etc/postgresql/17/certs/cert.pem
sudo chown postgres:postgres /etc/postgresql/17/certs/key.pem

sudo rm -r ../certificates/db
