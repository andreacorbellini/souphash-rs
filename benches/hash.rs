use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use souphash::SoupHasher;
use std::hint::black_box;

macro_rules! bench_hash {
    ( $c:expr, [] ) => {
        $c.bench_function("hash([])", |b| {
            b.iter(|| {
                let h = black_box(const { SoupHasher::new() });
                black_box(h.finish());
            })
        });
    };
    ( $c:expr, $input:expr ) => {
        $c.bench_function(concat!("hash(", stringify!($input), ")"), |b| {
            b.iter(|| {
                let mut h = black_box(const { SoupHasher::new() });
                h.extend(black_box($input));
                black_box(h.finish());
            })
        });
    };
}

fn hash_empty(c: &mut Criterion) {
    bench_hash!(c, []);
}

fn hash_i32_1(c: &mut Criterion) {
    bench_hash!(c, [0_i32]);
}

fn hash_i32_100(c: &mut Criterion) {
    bench_hash!(c, 0..100_i32);
}

fn hash_i32_10000(c: &mut Criterion) {
    bench_hash!(c, 0..10000_i32);
}

fn hash_u64_1(c: &mut Criterion) {
    bench_hash!(c, [0_u64]);
}

fn hash_u64_100(c: &mut Criterion) {
    bench_hash!(c, 0..100_u64);
}

fn hash_u64_10000(c: &mut Criterion) {
    bench_hash!(c, 0..10000_u64);
}

criterion_group!(
    hash_benches,
    hash_empty,
    hash_i32_1,
    hash_i32_100,
    hash_i32_10000,
    hash_u64_1,
    hash_u64_100,
    hash_u64_10000
);
criterion_main!(hash_benches);
