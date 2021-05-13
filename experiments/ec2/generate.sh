#!/bin/bash

# Generate crypto
( cd ../.. ; cargo r --release --bin generate_crypto -- $1 $2)

