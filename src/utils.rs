use rand::distr::{Alphanumeric, SampleString};

pub fn rand_string() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 10)
}
