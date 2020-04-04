#!/bin/sh

VERSION=0

TAG=mateusamin/protonvpn-cli-ng-build

docker build -f docker/build.dockerfile -t $TAG:latest -t $TAG:$VERSION .

# docker login --username mateusamin --password "$DOCKER_HUB_ACCESS_TOKEN"

# docker push $TAG:latest
# docker push $TAG:$VERSION