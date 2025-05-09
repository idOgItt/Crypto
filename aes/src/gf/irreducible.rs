use super::arithmetic::{Poly, poly_add, poly_mulmod, poly_powmod, poly_divmod, poly_mod};

/// Удаляет старшие нули
fn trim(p: &mut Poly) {
    while p.last().map_or(false, |b| !*b) {
        p.pop();
    }
}

/// Степень полинома
fn deg(p: &Poly) -> isize {
    for i in (0..p.len()).rev() {
        if p[i] {
            return i as isize;
        }
    }
    -1
}

/// Проверка, что полином монодальный (старший коэффициент = 1)
fn is_monic(p: &Poly) -> bool {
    p.last().copied().unwrap_or(false)
}

/// GCD полиномов через алгоритм Евклида
fn poly_gcd(mut a: Poly, mut b: Poly) -> Poly {
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

/// Проверка: является ли полином неприводимым над GF(2)
pub fn is_irreducible(poly: &Poly) -> bool {
    let n = deg(poly) as usize;
    if n < 1 || !is_monic(poly) {
        return false;
    }
    // x (полином "x")
    let x: Poly = vec![false, true];
    // 1) f(x) должно делить x^(2^n) - x
    let xp = poly_powmod(&x, 1 << n, poly);
    // проверяем, что (xp - x) mod f == 0
    let diff = poly_add(&xp, &x);
    let diff_mod = poly_mod(&diff, poly);
    if !diff_mod.is_empty() {
        return false;
    }
    // 2) для каждого делителя d < n: gcd(x^(2^d) - x, f) = 1
    // найдём простые делители n
    let mut d = 1;
    while d * d <= n {
        if n % d == 0 {
            for &k in &[d, n / d] {
                if k < n && k > 0 {
                    let xp_k = poly_powmod(&x, 1 << k, poly);
                    let g = poly_gcd(poly_add(&xp_k, &x), poly.clone());
                    // gcd должно быть константой 1
                    if !(g.len() == 1 && g[0]) {
                        return false;
                    }
                }
            }
        }
        d += 1;
    }
    true
}

/// Генерация всех неприводимых полиномов степени `n`
pub fn list_irreducibles(n: usize) -> Vec<Poly> {
    let mut res = Vec::new();
    // итерация по всем 2^n полиномам степени < n, но с монодальным битом
    let total = 1 << n;
    for mask in 0..total {
        let mut p = Vec::with_capacity(n + 1);
        for i in 0..n {
            p.push(((mask >> i) & 1) != 0);
        }
        // старший коэффициент = 1
        p.push(true);
        if is_irreducible(&p) {
            res.push(p);
        }
    }
    res
}
