# SoupHash: an order-indipendent hash function

[![Crate](https://img.shields.io/crates/v/souphash)](https://crates.io/crates/souphash) [![Documentation](https://img.shields.io/docsrs/souphash)](https://docs.rs/souphash/latest/souphash/) [![License](https://img.shields.io/crates/l/souphash)](https://choosealicense.com/licenses/unlicense/)

SoupHash is a non-cryptographic hash function whose output does not depend on
the order of the elements that are fed into it. It is ideal for:

* hashing of unordered collections (like *hash sets* and *hash maps*);
* hashing large collections in parallel, using multiple threads or processes,
  without locks or any form of synchronization.

SoupHash is based on the popular [SipHash] hashing algorithm. This repository
hosts the [Rust] implementation of SoupHash. Check the [crate documentation] to
learn more!

[SipHash]: https://en.wikipedia.org/wiki/SipHash
[Rust]: https://www.rust-lang.org/
[crate documentation]: https://docs.rs/souphash/latest/souphash/
