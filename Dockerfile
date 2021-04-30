# syntax=docker/dockerfile:experimental

FROM rust:1.51 as builder

ENV HOME=/home/root

WORKDIR $HOME/app

# Specify nightly toolchain. Need a specific version which provide rustfmt.

RUN rustup toolchain add nightly-2021-04-25

RUN rustup default nightly-2021-04-25

RUN rustup component add --toolchain nightly-2021-04-25 rustfmt clippy

RUN rustup update

# dummy files so we can compile and build depenencies
RUN USER=root cargo new dummy
COPY consensus-core/ consensus-core/

WORKDIR $HOME/app/dummy

# define dependencies for temporary build

COPY abft/Cargo.toml .
COPY Cargo.lock .
COPY /abft/proto $HOME/app/dummy/proto/
COPY /abft/build.rs $HOME/app/dummy/build.rs

# cache dependency compilation
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/root/app/target \
    cargo build --release

RUN rm src/*.rs   

COPY /abft/src $HOME/app/dummy/src/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/home/root/app/target \
    cargo build --release

RUN --mount=type=cache,target=/home/root/app/target cp target/release/abft $HOME/app/abft


#################################


FROM ubuntu:20.04

RUN apt-get update && apt-get install -y iproute2 iputils-ping 

ENV HOME=/home/root

WORKDIR $HOME/app/abft

COPY --from=builder $HOME/app/abft .

COPY abft/crypto/ crypto/

ENTRYPOINT ["./abft"]