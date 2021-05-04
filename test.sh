#!/bin/bash

for i in {1..40}; do
     rm log.txt && RUST_LOG=info cargo test --test abft_test --release -- --nocapture > log.txt;
done;