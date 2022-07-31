#!/bin/bash

# exit immediately when one publish failed
set -e

ROOT_DIR="$(dirname $0)"

pip install -r "$ROOT_DIR/requirements.txt"