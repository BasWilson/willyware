#!/bin/bash
# Script to randomize Go source code before compilation

OUTPUT_DIR="$1"
SOURCE_FILE="main.go"
RANDOM_ID=$(head -c 16 /dev/urandom | hexdump -e '4/4 "%08X" 1 "\n"')
TEMP_DIR="temp"
TEMP_FILE="$TEMP_DIR/main_$RANDOM_ID.go"

go mod tidy

# create temp dir if it doesn't exist
mkdir -p $TEMP_DIR || exit 1

# Generate 20 random comments
for i in {1..20}; do
    RANDOM_COMMENT="// Random comment $(head -c 16 /dev/urandom | hexdump -e '4/4 "%08X" 1 "\n"')"
    echo "$RANDOM_COMMENT" >> "$TEMP_FILE"
done
cat "$SOURCE_FILE" >> "$TEMP_FILE"

echo "Compiling to $OUTPUT_DIR/cheat.exe"

# Compile the program
GOOS=windows GOARCH=amd64 go build -o "$OUTPUT_DIR/cheat.exe" ./"$TEMP_FILE"