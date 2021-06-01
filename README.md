# Asynchronous Byzantine Fault Tolerance

A research prototype of HoneybadgerBFT in Rust, showcasing:

- Use of Threshold ECDSA signature scheme, over Threshold BLS signature scheme used in original Honeybadger implementation.
- Optimized choice of erasure coding parameters.
- Precomputation of public keys.

This project is part of a masters thesis. For more information regarding the project, see: ...

**NB: This is merely a research prototype. It is unfit for production use.** In particular, the precomputed signing material in Threshold ECDSA signature scheme is currently generated by a trusted dealer, and not discarded after use. 


The project is organized in the following way:

- **abft**: Implementation of ABFT (Honeybadger) algorithm
- **benches**: Benchmarks for various functionality.
- **consensus-core**: Core functionality used within abft.
- **experiments**: Scripts, configuration files etc. used for experimental evaluation of the implementation.