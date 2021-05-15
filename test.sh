#!/bin/bash

touch log.log

for i in {1..40}; do
     rm log.log && RUST_LOG=debug cargo test --test abft_test --release -- --nocapture > log.log;
done