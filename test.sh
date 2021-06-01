#!/bin/bash

touch log.log

for i in {1..10}; do
     cargo test --test abft_test --release -- --nocapture;
done