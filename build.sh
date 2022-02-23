#!/bin/bash
# Build Python Lambda Package
red=$(tput setaf 1)
green=$(tput setaf 2)
yellow=$(tput setaf 3)
reset=$(tput sgr0)

rm -r ./code/package/*
rm -r ./code/release/*
pip3 install -r ./code/requirements.txt --target ./code/package/
pushd .
cd ./code/package/
zip -r ../release/lambda_tenant_authorizer.zip .
popd
pwd
pushd .
cd ./code/
zip -g ./release/lambda_tenant_authorizer.zip ./tenant_authorizer.py
zip -g ./release/lambda_tenant_authorizer.zip ./auth_manager.py
popd