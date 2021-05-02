#!/bin/bash

# Generate crypto
( cd ../.. ; cargo r --bin generate_crypto -- $1 $2)

