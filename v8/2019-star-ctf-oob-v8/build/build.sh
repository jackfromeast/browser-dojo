#!/bin/bash

### =============== Variables Starts =============== ###

DOCKER_IMAGE="starctf-2019-oob-v8"
DIFF_FILE="oob.diff"
ARGS_FILE="args.gn"
V8_BASE_COMMIT="6dc88c191f5ecc5389dc26efa3ca0907faef3598"
V8_RELEASE_DIR="/build/v8/v8/out.gn/x64.release"
OUTPUT_FILES="d8,snapshot_blob.bin,natives_blob.bin"

### =============== Variables Ends =============== ###


SCRIPT_DIR="$(dirname "$(realpath "$0")")"
CHALLENGE_DIR="$SCRIPT_DIR/../challenge"
TEMPLATE_FILE="$SCRIPT_DIR/../../build.template.Dockerfile"
DOCKER_FILE="$SCRIPT_DIR/build.Dockerfile"

if [ ! -d "$CHALLENGE_DIR" ]; then
    echo "Creating challenge directory at $CHALLENGE_DIR"
    mkdir -p "$CHALLENGE_DIR"
fi

if [ ! -f "$TEMPLATE_FILE" ]; then
    echo "Template file $TEMPLATE_FILE does not exist!"
    exit 1
fi

echo "[+] Generating Dockerfile from template..."

if [ -f "$ARGS_FILE" ]; then
    COPY_ARGS="COPY ./$ARGS_FILE /build/v8/v8/out.gn/x64.release/\nRUN chmod 644 /build/v8/v8/out.gn/x64.release/$ARGS_FILE"
else
    COPY_ARGS="RUN chmod 644 out.gn/x64.release/args.gn"
fi

sed -e "s/{{ V8_BASE_COMMIT }}/$V8_BASE_COMMIT/g" \
    -e "s/{{ DIFF_FILE }}/$DIFF_FILE/g" \
    -e "s|{{ COPY_ARGS }}|$COPY_ARGS|g" \
    "$TEMPLATE_FILE" > "$DOCKER_FILE"

echo "[+] Building Docker image using build.Dockerfile..."
sudo docker build -t $DOCKER_IMAGE -f build.Dockerfile .


IFS=',' read -r -a FILE_ARRAY <<< "$OUTPUT_FILES"

TEST_FILES=""
COPY_FILES=""
for FILE in "${FILE_ARRAY[@]}"; do
    TEST_FILES="$TEST_FILES test -f $V8_RELEASE_DIR/$FILE &&"
    COPY_FILES="$COPY_FILES $V8_RELEASE_DIR/$FILE"
done

TEST_FILES=${TEST_FILES%"&&"}

echo "[+] Running the Docker container to compile V8 and copy files..."
sudo docker run --rm -v "$CHALLENGE_DIR:/challenge" $DOCKER_IMAGE bash -c " \
    $TEST_FILES && \
    cp $COPY_FILES /challenge/ \
" && echo "Files copied to $CHALLENGE_DIR" || echo "[!] Error: One or more required files are missing."

echo "[+] Removing Docker image $DOCKER_IMAGE..."
sudo docker rmi $DOCKER_IMAGE

echo "Build and copy process completed successfully."