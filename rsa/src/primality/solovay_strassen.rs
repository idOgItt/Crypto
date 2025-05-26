use crate::number_theory::{jacobi_symbol, mod_pow};
use crate::primality::PrimalityTest;
use num_bigint::{BigUint, BigInt, RandBigInt, ToBigInt, ToBigUint};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;

pub struct SolovayStrassenTest;

impl PrimalityTest for SolovayStrassenTest {
    fn run_iteration(&self, n: &BigUint) -> bool {
        let one = BigUint::one();
        let two = 2u8.to_biguint().unwrap();

        if *n <= two {
            return false;
        }

        if n == &BigUint::from(3u32) {
            return true;
        }

        let mut rng = thread_rng();
        let upper = n - &one;

        if two >= upper {
            return false;
        }

        let a = rng.gen_biguint_range(&two, &upper);

        let a_bigint = a.to_bigint().unwrap();
        let n_bigint = n.to_bigint().unwrap();
        if n_bigint.is_even() || n_bigint.is_zero() {
            return false;
        }

        let jacobi = jacobi_symbol(&a_bigint, &n_bigint);

        if jacobi == 0 {
            return false;
        }

        let exp = (n - &one) >> 1;
        let x = mod_pow(&a, &exp, n);

        let jacobi_mod_n = if jacobi == -1 {
            n - &one
        } else {
            BigUint::one()
        };

        x == jacobi_mod_n
    }
}
