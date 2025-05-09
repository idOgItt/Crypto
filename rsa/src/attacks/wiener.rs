use std::mem;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Подходящая дробь (k/d), встречающаяся в цепной дроби e/n
#[derive(Clone, Debug)]
pub struct ContinuedFractionTerm {
    pub k: BigUint,
    pub d: BigUint,
}

/// Результат атаки Винера
#[derive(Debug)]
pub struct WienerAttackResult {
    pub d: BigUint,
    pub phi_n: BigUint,
    pub candidates: Vec<ContinuedFractionTerm>,
}

/// Атака Винера на открытый ключ RSA
pub struct WienerAttack;

impl WienerAttack {
    /// Выполняет атаку по открытому ключу (n, e)
    pub fn attack(n: &BigUint, e: &BigUint) -> Option<WienerAttackResult> {
        // 1) Базовые проверки
        if e.is_zero() || n <= &BigUint::one() || e >= n {
            return None;
        }
        // Неэффективно для очень маленьких модулей
        if n.bits() < 16 {
            return None;
        }

        // 2) Разложение e/n в цепную дробь и построение конвергентов
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

            // пропускаем вырожденные дроби
            if k.is_zero() || d.is_zero() {
                continue;
            }

            // 3) Проверка совместимости: (e·d − 1) mod k == 0
            let ed_minus1 = e * &d - BigUint::one();
            if &ed_minus1 % &k != BigUint::zero() {
                continue;
            }
            let phi = &ed_minus1 / &k;

            // φ(n) должно быть меньше n
            if &phi >= n {
                continue;
            }

            // сохраняем этот кандидат
            candidates.push(ContinuedFractionTerm {
                k: k.clone(),
                d: d.clone(),
            });

            // 4) Проверка факторизации:
            //    s = n − φ(n) + 1, дискриминант = s² − 4n
            let s = n + BigUint::one() - &phi;

            //  ── вот здесь добавляем проверку, чтобы s*s >= 4*n ──
            let s2 = &s * &s;
            let four_n = BigUint::from(4u8) * n;
            if &s2 < &four_n {
                continue;
            }

            // теперь можно безопасно вычитать
            let discr = s2 - four_n;
            let root = discr.sqrt();
            // …


            if &root * &root != discr {
                continue;
            }

            if root > s {
                continue;
            }

            // p, q = (s ± root)/2
            let p = (&s + &root) / BigUint::from(2u8);
            let q = (&s - &root) / BigUint::from(2u8);
            if &p * &q == *n {
                // нашли первое рабочее d — сразу возвращаем
                return Some(WienerAttackResult {
                    d: d.clone(),
                    phi_n: phi,
                    candidates,
                });
            }
        }

        // 5) Если ни один кандидат не сработал — None
        None
    }
}
