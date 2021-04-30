#!/bin/bash

# Generate crypto
( cd .. ; cargo r --bin generate_crypto -- $1 $2)


# Rebuild Docker image
DOCKER_BUILDKIT=1 docker build -t abft -f ../. ../  


# Install helm chart


helm upgrade --set n_parties=$1 --set f_tolerance=$2 abft ./abft-chart