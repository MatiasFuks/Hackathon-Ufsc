#!/bin/bash

docker compose run --rm -w /workspace analyzer bash -c "
  python3 main.py /repos/python --python -o output/python
  python3 main.py /repos/php    --php    -o output/php
"
