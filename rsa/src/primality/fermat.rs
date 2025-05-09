use crate::number_theory::mod_pow;
use crate::primality::PrimalityTest;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use rand::thread_rng;

/// Структура, реализующая тест Ферма
pub struct FermatTest;

impl PrimalityTest for FermatTest {
    fn run_iteration(&self, n: &BigUint) -> bool {
        if *n <= BigUint::from(3u8) {
            return *n == BigUint::from(2u8) || *n == BigUint::from(3u8);
        }

        let mut rng = thread_rng();
        let one = BigUint::one();
        let two = &one + &one;

        let a = rng.gen_biguint_range(&two, &(n - &one));

        mod_pow(&a, &(n - &one), n) == one
    }
}
