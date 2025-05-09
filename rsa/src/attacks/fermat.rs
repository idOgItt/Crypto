use num_bigint::{BigUint, ToBigUint, ToBigInt};
use num_integer::Roots;
use num_traits::{One, ToPrimitive, Zero};
use crate::number_theory::extended_gcd;

/// Результат атаки Ферма
#[derive(Debug)]
pub struct FermatAttackResult {
    pub p: BigUint,
    pub q: BigUint,
    pub phi_n: BigUint,
    pub d: BigUint,
}

/// Атака Ферма на открытый ключ RSA
pub struct FermatAttack;

impl FermatAttack {
    /// Выполняет атаку по открытому ключу (n, e)
    pub fn attack(n: &BigUint, e: &BigUint) -> Option<FermatAttackResult> {
        // 1) Не пытаемся на очень маленьких n
        if n.bits() < 16 {
            return None;
        }

        // 2) Начальное a = ceil(sqrt(n))
        let mut a = n.sqrt();
        if &a * &a < *n {
            a += BigUint::one();
        }

        // 3) Ограничиваем количество шагов ~ n^(1/4)
        let max_iter = n.sqrt().sqrt().to_usize().unwrap_or(0);

        for i in 0..=max_iter {
            let ai = &a + BigUint::from(i);
            let b2 = &ai * &ai - n;
            let b = b2.sqrt();
            if &b * &b != b2 {
                continue;
            }

            // 4) Восстанавливаем p и q
            let p = &ai - &b;
            let q = &ai + &b;
            if &p * &q != *n {
                continue;
            }

            // 5) Вычисляем φ(n)
            let phi_n = (&p - BigUint::one()) * (&q - BigUint::one());

            // 6) Находим d = e⁻¹ mod φ(n)
            let (_, mut d, _) =
                extended_gcd(&e.to_bigint().unwrap(), &phi_n.to_bigint().unwrap());
            let phi_big = phi_n.to_bigint().unwrap();
            d = ((d % &phi_big) + &phi_big) % &phi_big;
            let d = d.to_biguint().unwrap();

            return Some(FermatAttackResult { p, q, phi_n, d });
        }

        // Если не нашли в пределах bound — считаем не уязвимым
        None
    }
}
