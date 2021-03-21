# syntax=docker/dockerfile:experimental

FROM rust:1.50 as builder

ENV HOME=/home/root

WORKDIR $HOME/app
RUN rustup component add rustfmt

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


FROM debian:buster-slim

ENV HOME=/home/root

WORKDIR $HOME/app/abft

COPY --from=builder $HOME/app/abft .

COPY abft/crypto/ crypto/

ENTRYPOINT ["./abft"]