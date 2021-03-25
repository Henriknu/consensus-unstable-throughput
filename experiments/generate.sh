#!/bin/bash

# Generate crypto
( cd .. ; cargo r --quiet --bin generate_crypto -- $1 &>/dev/null)


# Rebuild Docker image
DOCKER_BUILDKIT=1 docker build -t abft -f ../. ../  


# Install helm chart

N_PARTIES=$(($1 * 3 + 1))

helm upgrade --set n_parties=$N_PARTIES abft ./abft-chart