use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::mem;

#[derive(Clone, Debug)]
pub struct ContinuedFractionTerm {
    pub k: BigUint,
    pub d: BigUint,
}

#[derive(Debug)]
pub struct WienerAttackResult {
    pub d: BigUint,
    pub phi_n: BigUint,
    pub candidates: Vec<ContinuedFractionTerm>,
}

pub struct WienerAttack;

impl WienerAttack {
    pub fn attack(n: &BigUint, e: &BigUint) -> Option<WienerAttackResult> {
        if e.is_zero() || n <= &BigUint::one() || e >= n {
            return None;
        }
        if n.bits() < 16 {
            return None;
        }

        let mut a = e.clone();
        let mut b = n.clone();
        let (mut prev_k, mut k) = (BigUint::zero(), BigUint::one());
        let (mut prev_d, mut d) = (BigUint::one(), BigUint::zero());
        let mut candidates = Vec::new();

        while !b.is_zero() {
            let q = &a / &b;
            let r = &a % &b;
            a = b;
            b = r;

            let next_k = &q * &k + &prev_k;
            let next_d = &q * &d + &prev_d;
            prev_k = mem::replace(&mut k, next_k);
            prev_d = mem::replace(&mut d, next_d);

            if k.is_zero() || d.is_zero() {
                continue;
            }

            let ed_minus1 = e * &d - BigUint::one();
            if &ed_minus1 % &k != BigUint::zero() {
                continue;
            }
            let phi = &ed_minus1 / &k;

            if &phi >= n {
                continue;
            }

            candidates.push(ContinuedFractionTerm {
                k: k.clone(),
                d: d.clone(),
            });

            let s = n + BigUint::one() - &phi;

            let s2 = &s * &s;
            let four_n = BigUint::from(4u8) * n;
            if &s2 < &four_n {
                continue;
            }

            let discr = s2 - four_n;
            let root = discr.sqrt();

            if &root * &root != discr {
                continue;
            }

            if root > s {
                continue;
            }

            let p = (&s + &root) / BigUint::from(2u8);
            let q = (&s - &root) / BigUint::from(2u8);
            if &p * &q == *n {
                return Some(WienerAttackResult {
                    d: d.clone(),
                    phi_n: phi,
                    candidates,
                });
            }
        }
        None
    }
}
