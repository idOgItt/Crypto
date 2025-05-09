/// Полином над GF(2), представленный как вектор битов.
/// poly[i] — коэффициент при x^i
pub type Poly = Vec<bool>;

pub fn trim(p: &mut Poly) {
    while p.last().map_or(false, |b| !*b) {
        p.pop();
    }
}

pub fn is_monic(p: &Poly) -> bool {
    p.last().copied().unwrap_or(false)
}
pub fn deg(p: &Poly) -> isize {
    for i in (0..p.len()).rev() {
        if p[i] {
            return i as isize;
        }
    }
    -1
}

pub fn poly_gcd(mut a: Poly, mut b: Poly) -> Poly {
    trim(&mut a);
    trim(&mut b);
    while deg(&b) >= 0 {
        let (_, r) = poly_divmod(&a, &b);
        a = b;
        b = r;
    }
    trim(&mut a);
    a
}

/// Сложение полиномов в GF(2): XOR поразрядно
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let n = a.len().max(b.len());
    let mut r = vec![false; n]; 
    for i in 0..n {
        let ai = a.get(i).copied().unwrap_or(false);
        let bi = b.get(i).copied().unwrap_or(false);
        r[i] = ai ^ bi;
    }
    trim(&mut r);
    r
}

/// Умножение полиномов в GF(2)
pub fn poly_mul(a: &Poly, b: &Poly) -> Poly {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut r = vec![false; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai {
            for (j, &bj) in b.iter().enumerate() {
                if bj {
                    r[i + j] ^= true;
                }
            }
        }
    }
    trim(&mut r);
    r
}

/// Деление с остатком: (частное, остаток)
pub fn poly_divmod(dividend: &Poly, divisor: &Poly) -> (Poly, Poly) {
    let mut r = dividend.clone();
    trim(&mut r);
    let mut d = divisor.clone();
    trim(&mut d);
    let deg_d = deg(&d);    
    if deg_d < 0 {
        panic!("Division by zero polynomial");
    }
    let mut q = vec![false; r.len().max(d.len())];
    while deg(&r) >= deg_d {
        let shift = (deg(&r) - deg_d) as usize;
        q[shift] = true;
        for i in 0..=deg_d as usize {
            if d[i] {
                r[shift + i] ^= true;
            }
        }
        trim(&mut r);
    }
    trim(&mut q);
    (q, r)
}

/// Остаток от деления: a % modulus
pub fn poly_mod(a: &Poly, modulus: &Poly) -> Poly {
    let (_, rem) = poly_divmod(a, modulus);
    rem
}

/// Умножение с модулем: (a * b) mod modulus
pub fn poly_mulmod(a: &Poly, b: &Poly, modulus: &Poly) -> Poly {
    let product = poly_mul(a, b);
    poly_mod(&product, modulus)
}

/// Возведение в степень: a^exp mod modulus
pub fn poly_powmod(base: &Poly, exp: usize, modulus: &Poly) -> Poly {
    let mut result = vec![false; 1];
    result[0] = true;
    let mut power = base.clone();
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = poly_mulmod(&result, &power, modulus);
        } 
        power = poly_mulmod(&power, &power, modulus);
        e >>= 1;
    }
    trim(&mut result);
    result
}

/// Обратный элемент по модулю: a⁻¹ mod modulus
pub fn poly_inv(a: &Poly, modulus: &Poly) -> Poly {
    let mut r0 =  a.clone(); trim(&mut r0);
    let mut r1 = modulus.clone(); trim(&mut r1);
    let mut s0: Poly = vec![true];
    let mut s1: Poly = vec![false];
    while deg(&r1) >= 0 {
        let (q, r2) = poly_divmod(&r0, &r1);
        let s2 = poly_add(&s0, &poly_mul(&q, &s1));
        r0 = r1;
        r1 = r2;
        s0 = s1;
        s1 = s2;
    }
    if deg(&r0) != 0 || r0.get(0) != Some(&true) {
        panic!("No inverse exists for polynomial {:?} mod {:?}", a, modulus);
    }
    let mut inv = s0;
    inv = poly_mod(&inv, modulus);
    trim(&mut inv);
    inv
}
