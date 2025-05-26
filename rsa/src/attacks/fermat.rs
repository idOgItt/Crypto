use crate::number_theory::extended_gcd;
use num_bigint::{BigUint, ToBigInt, ToBigUint};
use num_integer::Roots;
use num_traits::{One, ToPrimitive};

#[derive(Debug)]
pub struct FermatAttackResult {
    pub p: BigUint,
    pub q: BigUint,
    pub phi_n: BigUint,
    pub d: BigUint,
}

pub struct FermatAttack;

impl FermatAttack {
    pub fn attack(n: &BigUint, e: &BigUint) -> Option<FermatAttackResult> {
        if n.bits() < 16 {
            return None;
        }
        
        let mut a = n.sqrt();
        if &a * &a < *n {
            a += BigUint::one();
        }

        let max_iter = n.sqrt().sqrt().to_usize().unwrap_or(0);

        for i in 0..=max_iter {
            let ai = &a + BigUint::from(i);
            let b2 = &ai * &ai - n;
            let b = b2.sqrt();
            if &b * &b != b2 {
                continue;
            }

            let p = &ai - &b;
            let q = &ai + &b;
            if &p * &q != *n {
                continue;
            }

            let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

            // search d = e⁻¹ mod φ(n)
            let (_, mut d, _) =
                extended_gcd(&e.to_bigint().unwrap(), &phi_n.to_bigint().unwrap());
            let phi_big = phi_n.to_bigint().unwrap();
            d = ((d % &phi_big) + &phi_big) % &phi_big;
            let d = d.to_biguint().unwrap();

            return Some(FermatAttackResult { p, q, phi_n, d });
        }
        None
    }
}
