use crate::number_theory::mod_pow;
use crate::primality::PrimalityTest;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_traits::{One, Zero};
use rand::thread_rng;

/// Структура, реализующая тест Миллера–Рабина
pub struct MillerRabinTest;

impl PrimalityTest for MillerRabinTest {
    fn run_iteration(&self, n: &BigUint) -> bool {
        let one = BigUint::one();
        let two = 2u32.to_biguint().unwrap();

        if *n <= two {
            return false;
        }

        let upper = n - &one;
        if &two >= &upper {
            return false; // защита от генерирования a ∈ [2, n-2], если диапазон пуст
        }

        let mut d = upper.clone();
        let mut s = 0u32;

        while &d % &two == Zero::zero() {
            d /= &two;
            s += 1;
        }

        if s == 0 {
            return false;
        }

        let mut rng = thread_rng();
        let a = rng.gen_biguint_range(&two, &upper);
        let mut x = mod_pow(&a, &d, n);

        if x == one || x == upper {
            return true;
        }

        for _ in 0..s - 1 {
            x = mod_pow(&x, &two, n);

            if x == upper {
                return true;
            }

            if x == one {
                return false;
            }
        }

        false
    }
}
