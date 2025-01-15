#!/bin/bash

IMAGE_NAME="bclab-dev-image"
CONTAINER_NAME="bclab-dev-container"

if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "[+] Building $IMAGE_NAME."
    export DOCKER_BUILDKIT=0
    docker build --platform linux/amd64 -t "$IMAGE_NAME" .
    if [ $? -ne 0 ]; then
        echo "[!] Fail to build $IMAGE_NAME."
        exit 1
    fi
else
    echo "[+] $IMAGE_NAME exists."
fi

if ! docker ps | grep "$CONTAINER_NAME" > /dev/null; then
    echo "[+] Creating $CONTAINER_NAME"
    docker run -it --net=host --rm -v "$(pwd):/workdir" --name "$CONTAINER_NAME" "$IMAGE_NAME"
else
    echo "[+] Entering $CONTAINER_NAME..."
    # CONTAINER_ID=$(docker ps -q -f name="$CONTAINER_NAME")

    docker exec -it "$CONTAINER_NAME" /bin/bash
fi