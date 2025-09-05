#![cfg_attr(not(test), no_std)]

//! SoupHash: an order-indipendent hash function
//!
//! SoupHash is a non-cryptographic hash function whose output does not depend on the order of the
//! elements that are fed into it. It is ideal for:
//!
//! * hashing of unordered collections (like [hash sets] and [hash maps]);
//! * hashing large collections in parallel, using multiple threads or processes, without locks or
//!   any form of synchronization.
//!
//! SoupHash is based on the popular [SipHash] hashing algorithm, specifically the SipHash 2-4
//! variant. At this moment the number of rounds used by SoupHash is not configurable (but this may
//! change in the future).
//!
//! Check the documentation for the [`SoupHasher` struct](SoupHasher) for more details and
//! examples.
//!
//! [hash sets]: https://doc.rust-lang.org/std/collections/struct.HashSet.html
//! [hash maps]: https://doc.rust-lang.org/std/collections/struct.HashMap.html
//! [SipHash]: https://en.wikipedia.org/wiki/SipHash
//!
//! # Examples
//!
//! ```
//! use souphash::SoupHasher;
//!
//! let mut hasher = SoupHasher::new();
//!
//! // Add a few elements in arbitrary order: elements of any type are
//! // accepted, as long as they implement `std::hash::Hash`
//! hasher.add(123);
//! hasher.add("abc");
//! hasher.add([1, 2, 3]);
//!
//! // Compute the final hash
//! let hash = hasher.finish();
//! assert_eq!(hash, 0xbe6f445accb8829d);
//!
//! // Now repeat the same procedure as above, but this time with the elements
//! // in a different order: notice that the final hash does not change
//! let mut hasher = SoupHasher::new();
//! hasher.add([1, 2, 3]);
//! hasher.add(123);
//! hasher.add("abc");
//! let hash = hasher.finish();
//! assert_eq!(hash, 0xbe6f445accb8829d);
//! ```

#![deny(unsafe_code)]
#![doc(test(attr(deny(warnings))))]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]
#![warn(unused_qualifications)]

mod buffer;

use crate::buffer::Buffer;
use core::cmp::min;
use core::error;
use core::fmt;
use core::hash::Hash;
use core::hash::Hasher;
use core::ops::BitOr;
use core::ops::BitOrAssign;

/// Converts the given slice of bytes to an `u64`, padding with zeros if the slice is too short.
///
/// # Panics
///
/// If `bytes` is larger than 8 bytes.
#[inline]
#[must_use]
const fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let len = bytes.len();
    let mut array = [0u8; 8];
    // Using `.split_at_mut(len).0` instead of `[..len]` to make this function `const`
    array.split_at_mut(len).0.copy_from_slice(bytes);
    u64::from_le_bytes(array)
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct State {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
}

impl State {
    #[inline]
    #[must_use]
    const fn zeroed() -> Self {
        Self {
            v0: 0,
            v1: 0,
            v2: 0,
            v3: 0,
        }
    }

    #[inline]
    #[must_use]
    const fn from_keys(k0: u64, k1: u64) -> Self {
        // This initializes the state exactly as described in the SipHash paper. I could have used
        // different constants to diversify SoupHash from SipHash, but I chose to reuse the same
        // just so that other implementors can easily reuse existing SipHash implementations.
        Self {
            v0: k0 ^ 0x736f6d6570736575,
            v1: k1 ^ 0x646f72616e646f6d,
            v2: k0 ^ 0x6c7967656e657261,
            v3: k1 ^ 0x7465646279746573,
        }
    }

    #[inline]
    const fn round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }

    const fn compress(&mut self, m: u64) {
        self.v3 ^= m;
        self.round();
        self.round();
        self.v0 ^= m;
    }

    const fn add(&mut self, other: &Self) {
        self.v0 = self.v0.wrapping_add(other.v0);
        self.v1 = self.v1.wrapping_add(other.v1);
        self.v2 = self.v2.wrapping_add(other.v2);
        self.v3 = self.v3.wrapping_add(other.v3);
    }

    #[must_use]
    const fn finalize(&mut self) -> u64 {
        self.v2 ^= 0xff;
        self.round();
        self.round();
        self.round();
        self.round();
        self.v0 ^ self.v1 ^ self.v2 ^ self.v3
    }
}

/// Hasher for a single element to be fed into [`SoupHasher`].
///
/// This hasher implements [`std::hash::Hasher`] and is used to hash a single element before adding
/// it to the [`SoupHasher`] state. It is used implicitly when you call [`SoupHasher::add()`] and
/// more explicitly when you call [`SoupHasher::add_with_hasher()`].
///
/// Under the hood, this struct implements SipHash 2-4. Calling [`finish()`](SoupHasher::finish) on
/// this struct will in fact return the SipHash 2-4 hash of the element.
///
/// [`std::hash::Hasher`]: https://doc.rust-lang.org/std/hash/trait.Hasher.html
///
/// # Examples
///
/// ```
/// use souphash::SoupElementHasher;
/// use souphash::SoupHasher;
/// use std::hash::Hash;
///
/// let mut hasher = SoupHasher::new();
///
/// // `add()` will implicitly construct a new `SoupElementHasher`, and use
/// // it to hash the element `123_u32`
/// hasher.add(123_u32);
///
/// // `add_with_hasher()` will construct a new `SoupElementHasher`, and
/// // pass a mutable reference to it to the closure
/// hasher.add_with_hasher(|elem_hasher: &mut SoupElementHasher| {
///     123_u32.hash(elem_hasher);
/// });
///
/// # assert_eq!(hasher.finish(), 0x8571678c724a7f01);
/// ```
#[derive(Clone, Debug)]
pub struct SoupElementHasher {
    state: State,
    buf: Buffer,
    count: u8,
}

impl SoupElementHasher {
    #[inline]
    #[must_use]
    const fn from_state(state: State) -> Self {
        Self {
            state,
            buf: Buffer::new(),
            count: 0,
        }
    }

    #[inline]
    const fn write_uint<const N: usize>(&mut self, x: u64) {
        self.count = self.count.wrapping_add(N as u8);
        if let Some(m) = self.buf.write(x, N) {
            self.state.compress(m);
        }
    }

    fn write_bytes(&mut self, mut bytes: &[u8]) {
        self.count = self.count.wrapping_add(bytes.len() as u8);

        // If the buffer is non-empty, fill it up completely, so that later we can call
        // `compress()` bypassing the buffer
        if !self.buf.is_empty() {
            let n = min(self.buf.available(), bytes.len());
            let (head, remaining) = bytes.split_at(n);
            if let Some(m) = self.buf.write_bytes(head) {
                self.state.compress(m);
            }
            bytes = remaining;
        }

        let (chunks, tail) = bytes.as_chunks::<8>();
        for c in chunks {
            let m = u64::from_le_bytes(*c);
            self.state.compress(m);
        }

        let _ = self.buf.write_bytes(tail);
    }

    #[must_use]
    const fn flush(mut self) -> State {
        let m = self.buf.take() | ((self.count as u64) << 56);
        self.state.compress(m);
        self.state
    }
}

impl Hasher for SoupElementHasher {
    fn write(&mut self, bytes: &[u8]) {
        self.write_bytes(bytes)
    }

    fn write_u8(&mut self, x: u8) {
        self.write_uint::<1>(x as u64)
    }

    fn write_u16(&mut self, x: u16) {
        self.write_uint::<2>(x as u64)
    }

    fn write_u32(&mut self, x: u32) {
        self.write_uint::<4>(x as u64)
    }

    fn write_u64(&mut self, x: u64) {
        self.write_uint::<8>(x)
    }

    fn write_usize(&mut self, x: usize) {
        const N: usize = size_of::<usize>();
        self.write_uint::<N>(x as u64)
    }

    fn finish(&self) -> u64 {
        self.clone().flush().finalize()
    }
}

/// Implementation for SoupHash.
///
/// The main way to add elements to be hashed to `SoupHasher` is to call
/// [`add()`](SoupHasher::add), which accepts any object implementing [`std::hash::Hash`].
///
/// Two (or more) instances of `SoupHasher` can also be merged together using the
/// [`combine()`](SoupHasher::combine) method. Combining multiple `SoupHasher` objects together has
/// the same effect of adding all the elements that were originally fed into the individual
/// objects, into the resulting `SoupHasher`. This is particularly useful when hashing over
/// multiple threads or coroutines.
///
/// Note that this struct does not implement [`std::hash::Hasher`]. The reason being that
/// `SoupHasher` needs to know when each element starts and ends, and `Hasher` does not give any
/// way to provide that information.
///
/// [`std::hash::Hash`]: https://doc.rust-lang.org/std/hash/trait.Hash.html
/// [`std::hash::Hasher`]: https://doc.rust-lang.org/std/hash/trait.Hasher.html
///
/// # Examples
///
/// ## Hashing elements directly
///
/// If you have some elements (not necessarily of the same type), you hash them one-by-one using
/// [`SoupHasher::add()`]:
///
/// ```
/// use souphash::SoupHasher;
///
/// // Initialize the hasher with the default keys
/// let mut hasher = SoupHasher::new();
///
/// // Add a few elements; element can have any type, as long as
/// // they implement the `Hash` trait
/// hasher.add(123);
/// hasher.add("abc");
/// hasher.add([1, 2, 3]);
/// hasher.add(('a', "tuple"));
///
/// // Once done, the final hash can be retrieved with `finish()`
/// let hash = hasher.finish();
/// assert_eq!(hash, 0x7105ed1ba4bbdf8e);
///
/// // Now try again, but with the elements in a different order:
/// // the output will be the same as before!
/// let mut hasher = SoupHasher::new();
/// hasher.add("abc");
/// hasher.add(('a', "tuple"));
/// hasher.add([1, 2, 3]);
/// hasher.add(123);
/// assert_eq!(hasher.finish(), 0x7105ed1ba4bbdf8e);
/// ```
///
/// ## Hashing collections or iterators
///
/// If you have an iterable collection, you can also use [`extend()`](SoupHasher::extend):
///
/// ```
/// use souphash::SoupHasher;
/// let mut hasher = SoupHasher::new();
///
/// hasher.extend([1, 2, 3]); // equivalent to `add(1); add(2); add(3);`
///
/// assert_eq!(hasher.finish(), 0xf5b11a781673c093);
/// ```
///
/// ## Hashing a `HashSet` or a `HashMap`
///
/// The order of the elements returned when iterating a [`HashSet`] is not specified, but this
/// doesn't matter with SoupHash because it's order-indipendent:
///
/// [`HashSet`]: https://doc.rust-lang.org/std/collections/struct.HashSet.html
///
/// ```
/// use souphash::SoupHasher;
/// use std::collections::HashSet;
///
/// let set = HashSet::from(['a', 'b', 'c']);
///
/// let mut hasher = SoupHasher::new();
/// hasher.extend(&set);
/// let hash = hasher.finish();
///
/// assert_eq!(hash, 0x525ed002939725bf);
/// ```
///
/// The story with [`HashMap`] is very similar as the one for [`HashSet`]:
///
/// [`HashMap`]: https://doc.rust-lang.org/std/collections/struct.HashMap.html
///
/// ```
/// use souphash::SoupHasher;
/// use std::collections::HashMap;
///
/// let map = HashMap::from([('a', 0), ('b', 1), ('c', 2)]);
///
/// let mut hasher = SoupHasher::new();
/// hasher.extend(&map);
/// let hash = hasher.finish();
///
/// assert_eq!(hash, 0x6d5a22d6129ae9e1);
/// ```
///
/// ## Hashing large collections in parallel
///
/// If you have a large collection to hash, and order is not important to you, then you can spin
/// multiple threads, each owning its own [`SoupHasher`] object. Each thread will then process a
/// slice of the collection, mutating the state of the `SoupHasher`. Once every thread has
/// finished, the resulting `SoupHasher` objects can be merged together to produce a single, final
/// hash.
///
/// ### Using `rayon`
///
/// The code below uses [rayon]'s [`fold_with()`] to process the elements in separate threads
/// (`fold_with()` takes care of automatically cloning the initial `SoupHasher`), and then
/// [`reduce_with()`] to combine all the `SoupHasher` objects together.
///
/// [rayon]: https://docs.rs/rayon/1.11.0/rayon/
/// [`fold_with()`]: https://docs.rs/rayon/1.11.0/rayon/iter/trait.ParallelIterator.html#method.fold_with
/// [`reduce_with()`]: https://docs.rs/rayon/1.11.0/rayon/iter/trait.ParallelIterator.html#method.reduce_with
///
/// ```
/// use rayon::iter::IntoParallelIterator;
/// use rayon::iter::ParallelIterator;
/// use souphash::SoupHasher;
///
/// let large_data_set = 0..100_000_000;
///
/// let hash = large_data_set
///     .into_par_iter()
///     .fold_with(SoupHasher::new(), |mut hasher, item| {
///         hasher.add(item);
///         hasher
///     })
///     .reduce_with(|a, b| a.combine(&b))
///     .unwrap()
///     .finish();
///
/// assert_eq!(hash, 0xab2e22aa52a78815);
/// ```
///
/// Note that the code above produces the same result as processing each element serially, in a
/// single thread, using a single `SoupHash` (but it's much slower):
///
/// ```
/// use souphash::SoupHasher;
///
/// let mut h = SoupHasher::new();
/// h.extend(0..100_000_000);
/// assert_eq!(h.finish(), 0xab2e22aa52a78815);
/// ```
///
/// ### Using `std::thread`
///
/// The code below spins up 4 threads to process a relatively large array. Each thread gets a
/// slice of the array, constructs its own `SoupHasher`, and feeds the slice into it. At the end,
/// the resulting `SoupHasher` objects are combined together.
///
/// ```
/// use souphash::SoupHasher;
/// use std::thread;
///
/// // Not really slices, but you get the idea...
/// let slices = [
///     0..25_000_000,
///     25_000_000..50_000_000,
///     50_000_000..75_000_000,
///     75_000_000..100_000_000,
/// ];
///
/// let handles = slices
///     .into_iter()
///     .map(|s| {
///         thread::spawn(move || {
///             let mut hasher = SoupHasher::new();
///             hasher.extend(s);
///             hasher
///         })
///     })
///     .collect::<Vec<_>>();
///
/// let hash = handles
///     .into_iter()
///     .map(|handle| handle.join().unwrap())
///     .reduce(|a, b| a.combine(&b))
///     .unwrap()
///     .finish();
///
/// assert_eq!(hash, 0xab2e22aa52a78815);
/// ```
#[derive(Clone, Debug)]
pub struct SoupHasher {
    state: State,
    count: u64,
    elem_hasher_state: State,
}

impl SoupHasher {
    /// Creates a new hasher with zeroed keys.
    ///
    /// This is equivalent to [`SoupHasher::with_keys(0, 0)`](SoupHasher::with_keys).
    ///
    /// # Examples
    ///
    /// ```
    /// use souphash::SoupHasher;
    /// let hasher = SoupHasher::new();
    /// # assert_eq!(hasher.finish(), 0x1e924b9d737700d7);
    /// ```
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self::with_keys(0, 0)
    }

    /// Creates a new hasher with the given keys specified as a pair of [`u64`].
    ///
    /// # Examples
    ///
    /// ```
    /// use souphash::SoupHasher;
    /// let hasher = SoupHasher::with_keys(123, 456);
    /// # assert_eq!(hasher.finish(), 0x8c5254ec1f1e0dee);
    /// ```
    #[inline]
    #[must_use]
    pub const fn with_keys(k0: u64, k1: u64) -> Self {
        Self {
            state: State::zeroed(),
            count: 0,
            elem_hasher_state: State::from_keys(k0, k1),
        }
    }

    /// Creates a new hasher with the given key specified as bytes.
    ///
    /// The bytes are interpreted as two little-endian [`u64`] integers.
    ///
    /// # Examples
    ///
    /// ```
    /// use souphash::SoupHasher;
    /// let hasher = SoupHasher::with_key([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
    /// # assert_eq!(hasher.finish(), 0x8f311eb6e523c5eb);
    /// ```
    #[inline]
    #[must_use]
    pub const fn with_key(k: [u8; 16]) -> Self {
        let (k0, k1) = k.split_at(8);
        debug_assert!(k0.len() == 8);
        debug_assert!(k1.len() == 8);
        let k0 = bytes_to_u64(k0);
        let k1 = bytes_to_u64(k1);
        Self::with_keys(k0, k1)
    }

    /// Hashes an element and adds it to the state.
    ///
    /// The element can be of any type as long as it implements [`std::hash::Hash`]. The order of
    /// the elements passed to `add()` does not influence the final hash.
    ///
    /// Use [`finish()`](SoupHasher::finish) to retrieve the final hash.
    ///
    /// [`std::hash::Hash`]: https://doc.rust-lang.org/std/hash/trait.Hash.html
    ///
    /// # Example
    ///
    /// ```
    /// use souphash::SoupHasher;
    /// let mut hasher = SoupHasher::new();
    /// hasher.add(123);
    /// hasher.add(&123);
    /// hasher.add("abc");
    /// hasher.add(vec!['a', 'b', 'c']);
    /// hasher.add(());
    /// hasher.add(&mut true);
    /// # assert_eq!(hasher.finish(), 0xa8d6e717807da8d1);
    /// ```
    #[inline]
    pub fn add<T: Hash>(&mut self, elem: T) {
        self.add_with_hasher(move |hasher| elem.hash(hasher));
    }

    /// Hashes an element and adds it to the state, allowing direct manipulation of the element
    /// hasher.
    ///
    /// This method is an alternative to [`add()`](SoupHasher::add) that allows you to write
    /// directly to the element hasher, without the need to pass (or even construct) the actual
    /// element.
    ///
    /// This method accepts a closure that will get called with a mutable reference to a
    /// [`SoupElementHasher`] object, which implements [`std::hash::Hasher`]. The closure does not
    /// need to call [`SoupElementHasher::finish()`]: this will be done automatically once the
    /// closure returns.
    ///
    /// Use [`finish()`](SoupHasher::finish) to retrieve the final hash.
    ///
    /// [`std::hash::Hasher`]: https://doc.rust-lang.org/std/hash/trait.Hasher.html
    ///
    /// # Example
    ///
    /// ```
    /// use souphash::SoupHasher;
    /// use std::hash::Hasher;
    ///
    /// let mut hasher = SoupHasher::new();
    ///
    /// hasher.add_with_hasher(|elem_hasher| {
    ///     // Note that this call is considered as adding a single element composed as
    ///     // the concatenation of `123` and `b"abc"`. This is NOT the same as writing
    ///     // `hasher.add(123); hasher.add(b"abc");`: `SoupHasher` is order-indipendent,
    ///     // but `SoupElementHasher` is not.
    ///     elem_hasher.write_u32(123);
    ///     elem_hasher.write(b"abc");
    /// });
    /// # assert_eq!(hasher.finish(), 0x4594012f61bc919);
    /// ```
    pub fn add_with_hasher<F>(&mut self, f: F)
    where
        F: FnOnce(&mut SoupElementHasher),
    {
        let mut elem_hasher = SoupElementHasher::from_state(self.elem_hasher_state.clone());
        f(&mut elem_hasher);

        let mut elem_state = elem_hasher.flush();
        let _ = elem_state.finalize();
        self.state.add(&elem_state);

        self.count = self.count.wrapping_add(1);
    }

    /// Computes the final hash.
    ///
    /// This method does not alter the internal state of the hasher, and may be called multiple
    /// times through the lifetime of the hasher.
    ///
    /// # Examples
    ///
    /// ```
    /// use souphash::SoupHasher;
    ///
    /// let mut hasher = SoupHasher::new();
    ///
    /// hasher.add(123);
    /// hasher.add(&123);
    /// hasher.add("abc");
    /// hasher.add(vec!['a', 'b', 'c']);
    /// hasher.add(());
    /// hasher.add(&mut true);
    ///
    /// let hash = hasher.finish();
    /// assert_eq!(hash, 0xa8d6e717807da8d1);
    /// ```
    #[must_use]
    pub fn finish(&self) -> u64 {
        let mut state = self.state.clone();
        state.add(&self.elem_hasher_state);
        state.compress(self.count);
        state.finalize()
    }

    /// Merges the state of two hashers, producing a third one that has a combined state.
    ///
    /// The resulting hasher can be thought of containing all the information about the elements
    /// that were added to either `self` or `other`.
    ///
    /// `combine()` is a commutative operation, meaning that `a.combine(&b)` produces the same
    /// final state as `b.combine(&a)`.
    ///
    /// This method is useful when computing the hash of a large data set over multiple threads:
    /// each thread can update its own `SoupHasher` with a slice of the data, and then at the end
    /// the final hash can be computed by combining all the per-thread `SoupHasher`s.
    ///
    /// # Panics
    ///
    /// If `self` and `other` were constructed using different keys. See
    /// [`try_combine()`](SoupHasher::try_combine) for a panic-free variant of this method.
    ///
    /// # Alternative syntax
    ///
    /// `combine()` can also be written using the `|` operator. The following lines of code are
    /// equivalent:
    ///
    /// ```
    /// # #![allow(unused_variables)]
    /// # use souphash::SoupHasher;
    /// # let a = SoupHasher::new();
    /// # let b = SoupHasher::new();
    /// let c = a.combine(&b);
    /// let c = a | b;
    /// ```
    ///
    /// # Examples
    ///
    /// The following example illustrates how `combine()` can be used to split the hash computation
    /// between two hashers, and it's equivalent to adding to all the elements to a single hasher:
    ///
    /// ```
    /// use souphash::SoupHasher;
    ///
    /// let mut a = SoupHasher::new();
    /// let mut b = SoupHasher::new();
    ///
    /// a.add('a');
    /// b.add('b');
    /// assert_eq!(a.combine(&b).finish(), 0x9ca94f681c50429e);
    /// assert_eq!(b.combine(&a).finish(), 0x9ca94f681c50429e);
    ///
    /// let mut c = SoupHasher::new();
    /// c.add('a');
    /// c.add('b');
    /// assert_eq!(c.finish(), 0x9ca94f681c50429e);
    /// ```
    ///
    /// Mixing hashers with different keys will result in a panic:
    ///
    /// ```should_panic
    /// use souphash::SoupHasher;
    ///
    /// let a = SoupHasher::with_keys(1, 2);
    /// let b = SoupHasher::with_keys(3, 4);
    /// let _ = a.combine(&b); // panics!
    /// ```
    ///
    /// This is an example of how hash computations can be split over multiple threads using the
    /// popular [rayon] crate:
    ///
    /// [rayon]: https://docs.rs/rayon/1.11.0/rayon/
    ///
    /// ```
    /// use rayon::iter::IntoParallelIterator;
    /// use rayon::iter::ParallelIterator;
    /// use souphash::SoupHasher;
    ///
    /// let large_data_set = 0..100_000_000;
    ///
    /// let hash = large_data_set
    ///     .into_par_iter()
    ///     .fold_with(SoupHasher::new(), |mut hasher, item| {
    ///         hasher.add(item);
    ///         hasher
    ///     })
    ///     .reduce_with(|a, b| a.combine(&b))
    ///     .unwrap()
    ///     .finish();
    ///
    /// assert_eq!(hash, 0xab2e22aa52a78815);
    ///
    /// // The parallel code above produces the same result as the following serial code:
    ///
    /// let mut h = SoupHasher::new();
    /// h.extend(0..100_000_000);
    /// assert_eq!(h.finish(), 0xab2e22aa52a78815);
    /// ```
    #[must_use]
    pub fn combine(&self, other: &Self) -> Self {
        self.try_combine(other).unwrap()
    }

    /// Merges the state of two hashers, producing a third one that has a combined state. Returns
    /// an error if the two input hashers have different keys.
    ///
    /// This method has the same semantics as [`combine()`](SoupHasher::combine), except that it
    /// does not panic if the two input hashers were constructed using different keys.
    pub fn try_combine(&self, other: &Self) -> Result<Self, KeyMismatch> {
        if self.elem_hasher_state != other.elem_hasher_state {
            return Err(KeyMismatch);
        }

        let mut result = self.clone();
        result.state.add(&other.state);
        result.count = self.count.wrapping_add(other.count);
        Ok(result)
    }
}

impl Default for SoupHasher {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Hash> Extend<T> for SoupHasher {
    fn extend<I>(&mut self, it: I)
    where
        I: IntoIterator<Item = T>,
    {
        for elem in it.into_iter() {
            self.add(elem);
        }
    }
}

impl BitOr<SoupHasher> for SoupHasher {
    type Output = SoupHasher;

    /// Merges the state of two hashers, producing a third one that has a combined state.
    ///
    /// This is equivalent to calling [`combine()`](SoupHasher::combine).
    #[inline]
    fn bitor(self, other: SoupHasher) -> Self::Output {
        self.combine(&other)
    }
}

impl BitOr<&SoupHasher> for SoupHasher {
    type Output = SoupHasher;

    /// Merges the state of two hashers, producing a third one that has a combined state.
    ///
    /// This is equivalent to calling [`combine()`](SoupHasher::combine).
    #[inline]
    fn bitor(self, other: &SoupHasher) -> Self::Output {
        self.combine(other)
    }
}

impl BitOr<SoupHasher> for &SoupHasher {
    type Output = SoupHasher;

    /// Merges the state of two hashers, producing a third one that has a combined state.
    ///
    /// This is equivalent to calling [`combine()`](SoupHasher::combine).
    #[inline]
    fn bitor(self, other: SoupHasher) -> Self::Output {
        self.combine(&other)
    }
}

impl BitOr<&SoupHasher> for &SoupHasher {
    type Output = SoupHasher;

    /// Merges the state of two hashers, producing a third one that has a combined state.
    ///
    /// This is equivalent to calling [`combine()`](SoupHasher::combine).
    #[inline]
    fn bitor(self, other: &SoupHasher) -> Self::Output {
        self.combine(other)
    }
}

impl BitOrAssign<Self> for SoupHasher {
    /// Merges the state of an hasher into this one.
    ///
    /// This is equivalent to calling [`combine()`](SoupHasher::combine) and replacing `self` with
    /// the result.
    #[inline]
    fn bitor_assign(&mut self, other: Self) {
        *self = self.combine(&other);
    }
}

impl BitOrAssign<&Self> for SoupHasher {
    /// Merges the state of an hasher into this one.
    ///
    /// This is equivalent to calling [`combine()`](SoupHasher::combine) and replacing `self` with
    /// the result.
    #[inline]
    fn bitor_assign(&mut self, other: &Self) {
        *self = self.combine(other);
    }
}

/// Error returned by [`SoupHasher::try_combine()`] when trying to merge two hashers constructed
/// with different keys.
#[derive(Debug)]
pub struct KeyMismatch;

impl fmt::Display for KeyMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "keys don't match".fmt(f)
    }
}

impl error::Error for KeyMismatch {}

#[cfg(test)]
mod tests {
    use crate::SoupElementHasher;
    use crate::SoupHasher;
    use crate::State;
    use std::collections::HashSet;
    use std::hash::Hasher;

    #[test]
    fn siphash_vectors() {
        let s = State::from_keys(0x0706050403020100, 0x0f0e0d0c0b0a0908);
        let mut h = SoupElementHasher::from_state(s);
        assert_eq!(h.state.v0, 0x7469686173716475);
        assert_eq!(h.state.v1, 0x6b617f6d656e6665);
        assert_eq!(h.state.v2, 0x6b7f62616d677361);
        assert_eq!(h.state.v3, 0x7b6b696e727e6c7b);
        h.write(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e,
        ]);
        assert_eq!(h.finish(), 0xa129ca6149be45e5);
    }

    macro_rules! hash {
        [] => {
            SoupHasher::new().finish()
        };
        [ $( $elem:expr ),+ $(,)? ] => {{
            let mut h = SoupHasher::new();
            $( h.add($elem); )+
            h.finish()
        }}
    }

    macro_rules! assert_hash_eq {
        ( [ $( $elem:expr ),* $(,)? ] => $expected:expr ) => {{
            let actual = hash![ $( $elem ),* ];
            let expected = $expected;
            assert_eq!(actual, expected, "hash mismatch: 0x{actual:x} != 0x{expected:x}");
        }}
    }

    #[test]
    fn vectors() {
        assert_hash_eq!([] => 0x1e924b9d737700d7);

        assert_hash_eq!([()] => 0x6a93544f73268a1d);
        assert_hash_eq!([(), ()] => 0xe932b92cdd6952c);
        assert_hash_eq!([(), (), ()] => 0xe808f7c71defaf9e);
        assert_hash_eq!([(), (), (), ()] => 0xfbb7281c4b1a99ba);
        assert_hash_eq!([(), (), (), (), ()] => 0xa7f4e0cf94fce9dd);

        assert_hash_eq!([0] => 0x1cf09c9565dfbff4);
        assert_hash_eq!([0, 0] => 0x4e341d5d8eacf71c);
        assert_hash_eq!([0, 0, 0] => 0x76671729dfb6e001);
        assert_hash_eq!([0, 0, 0, 0] => 0xc3b488b49f3b7aa7);
        assert_hash_eq!([0, 0, 0, 0, 0] => 0xb890466d03badf45);

        assert_hash_eq!([""] => 0x9d15b53333498468);
        assert_hash_eq!([b""] => 0xf11858ac1f1c713f);

        assert_hash_eq!([123] => 0xfa1d43c971e02556);
        assert_hash_eq!(["abc"] => 0xa5b4dab870ae41a8);

        assert_hash_eq!([123, "abc"] => 0x29400d763b6fa6c2);
        assert_hash_eq!(["abc", 123] => 0x29400d763b6fa6c2);

        assert_hash_eq!([(), 0, ""] => 0x7a82eb8ad5f1c23e);
        assert_hash_eq!([(), "", 0] => 0x7a82eb8ad5f1c23e);
        assert_hash_eq!([0, "", ()] => 0x7a82eb8ad5f1c23e);
        assert_hash_eq!([0, (), ""] => 0x7a82eb8ad5f1c23e);
        assert_hash_eq!(["", (), 0] => 0x7a82eb8ad5f1c23e);
        assert_hash_eq!(["", 0, ()] => 0x7a82eb8ad5f1c23e);
    }

    #[test]
    fn combine() {
        let mut a = SoupHasher::new();
        let mut b = SoupHasher::new();

        a.add("hello");
        b.add(1234567);

        assert_eq!(a.finish(), 0x83675ec42551b23d);
        assert_eq!(b.finish(), 0xab8b024a3c2bde71);

        assert_eq!(a.combine(&b).finish(), 0x9986fcb17df59b52);
        assert_eq!(b.combine(&a).finish(), 0x9986fcb17df59b52);
        assert_eq!((&a | &b).finish(), 0x9986fcb17df59b52);
        assert_eq!((&b | &a).finish(), 0x9986fcb17df59b52);

        let mut c = a.clone();
        c |= &b;
        assert_eq!(c.finish(), 0x9986fcb17df59b52);

        let mut c = b.clone();
        c |= &a;
        assert_eq!(c.finish(), 0x9986fcb17df59b52);
    }

    #[test]
    fn uniqueness() {
        let mut hasher = SoupHasher::new();
        let mut seen = HashSet::new();
        seen.insert(hasher.finish());
        for i in 0..100_000 {
            hasher.add(i);
            let hash = hasher.finish();
            assert!(seen.insert(hash), "0x{hash:x} repeated at step {i}");
        }
    }

    #[test]
    fn key_dependance() {
        let mut seen = HashSet::new();

        for k0 in 0..100 {
            for k1 in 0..100 {
                let mut hasher = SoupHasher::with_keys(k0, k1);

                let hash = hasher.finish();
                assert!(
                    seen.insert(hash),
                    "0x{hash:x} repeated with k0={k0}, k1={k1} (no input)"
                );

                for i in 0..100 {
                    hasher.add(i);
                    let hash = hasher.finish();
                    assert!(
                        seen.insert(hash),
                        "0x{hash:x} repeated at step {i} with k0={k0}"
                    );
                }
            }
        }
    }
}
