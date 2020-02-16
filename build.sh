#!/bin/bash
NEW_UUID=$(cat /dev/urandom | LC_CTYPE=C tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
export GOOS=linux && go build -o sample-auth main.go
docker build -t "sample-auth" .
docker tag sample-auth localhost:5010/sample-auth:${NEW_UUID}
docker push localhost:5010/sample-auth:${NEW_UUID}