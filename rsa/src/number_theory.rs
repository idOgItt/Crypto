use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{One, Zero, Signed, ToPrimitive};

pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a = a.clone();
    let mut b = b.clone();
    while !b.is_zero() {
        let r = a % &b;
        a = b;
        b = r;
    }
    a
}

/// Возвращает (g, x, y) такие что: ax + by = g = gcd(a, b)
pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());

    while !r.is_zero() {
        let q = &old_r / &r;

        let tmp_r = old_r - &q * &r;
        old_r = r;
        r = tmp_r;

        let tmp_s = old_s - &q * &s;
        old_s = s;
        s = tmp_s;

        let tmp_t = old_t - &q * &t;
        old_t = t;
        t = tmp_t;
    }

    (old_r, old_s, old_t)
}

/// Возведение в степень по модулю: base^exp mod modulus
pub fn mod_pow(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_zero() {
        return BigUint::zero();
    }
    let mut base = base.clone() % modulus;
    let mut exp = exponent.clone();
    let mut result = BigUint::one();

    while !exp.is_zero() {
        if &exp % 2u8 == BigUint::one() {
            result = (result * &base) % modulus;
        }
        base = (&base * &base) % modulus;
        exp >>= 1;
    }
    result
}

/// Символ Лежандра (a|p), p — нечётное простое
pub fn legendre_symbol(a: &BigInt, p: &BigInt) -> i32 {
    if p <= &BigInt::one() || !p.is_odd() {
        panic!("p must be an odd prime");
    }

    // a_mod = a mod p, но в диапазоне [0, p-1]
    let a_mod = ((a % p) + p) % p;
    let a_mod_uint = a_mod.to_biguint().unwrap();

    let modulus = p.to_biguint().unwrap();
    // Legendre
    let exp = (&modulus - BigUint::one()) >> 1;

    let res = mod_pow(&a_mod_uint, &exp, &modulus);

    if res.is_zero() {
        0
    } else if res == BigUint::one() {
        1
    } else {
        -1
    }
}

/// Символ Якоби (a|n), n — нечётное положительное
pub fn jacobi_symbol(a: &BigInt, n: &BigInt) -> i32 {
    if n.is_even() || *n <= BigInt::zero() {
        panic!("n must be an odd positive integer");
    }

    // Приводим a к диапазону [0, n-1]
    let mut a = a.clone() % n;
    if a.is_negative() {
        a += n;
    }
    let mut n = n.clone();
    let mut result = 1;

    while a != BigInt::zero() {
        while a.is_even() {
            a >>= 1;
            // если n ≡ 3 или 5 (mod 8) — меняем знак
            let n_mod_8 = (&n % 8u8).to_u8().unwrap();
            if n_mod_8 == 3 || n_mod_8 == 5 {
                result = -result;
            }
        }

        std::mem::swap(&mut a, &mut n);
        // Jacobi
        if &a % 4u8 == BigInt::from(3) && &n % 4u8 == BigInt::from(3) {
            result = -result;
        }
        a %= &n;
    }

    if n == BigInt::one() {
        result
    } else {
        0
    }
}
