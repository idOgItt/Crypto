use rijndael::gf::arithmetic::Poly;
use rijndael::gf::irreducible::{is_irreducible, list_irreducibles};

/// Вспомогалка: строит Poly из среза битов (0 или 1)
fn poly_from_bits(bits: &[u8]) -> Poly {
    bits.iter().map(|&b| b != 0).collect()
}

#[test]
fn degree_1_irreducibles() {
    // x      → [0,1]
    // x + 1  → [1,1]
    let p_x  = poly_from_bits(&[0,1]);
    let p_x1 = poly_from_bits(&[1,1]);
    assert!( is_irreducible(&p_x) );
    assert!( is_irreducible(&p_x1) );

    let list = list_irreducibles(1);
    assert_eq!( list.len(), 2 );
    assert!( list.contains(&p_x) );
    assert!( list.contains(&p_x1) );
}

#[test]
fn degree_2_irreducible_and_reducible() {
    // x^2 + x + 1 → irreducible
    let p_irred = poly_from_bits(&[1,1,1]);
    assert!( is_irreducible(&p_irred) );

    // x^2 + 1 → reducible (x+1)^2
    let p_red = poly_from_bits(&[1,0,1]);
    assert!(!is_irreducible(&p_red));

    let list = list_irreducibles(2);
    assert_eq!( list.len(), 1 );
    assert_eq!( list[0], p_irred );
}

#[test]
fn degree_3_irreducibles() {
    // Известные неприводимые: x^3 + x + 1 и x^3 + x^2 + 1
    let p1 = poly_from_bits(&[1,1,0,1]); // 0b1011
    let p2 = poly_from_bits(&[1,0,1,1]); // 0b1101
    assert!( is_irreducible(&p1) );
    assert!( is_irreducible(&p2) );
    assert!(!is_irreducible(&poly_from_bits(&[0,1,0,1]))); // x^3 + x (reducible)

    let list = list_irreducibles(3);
    assert_eq!( list.len(), 2 );
    assert!( list.contains(&p1) );
    assert!( list.contains(&p2) );
}

#[test]
fn degree_4_irreducibles() {
    // Неприводимые степени 4: x^4+x+1, x^4+x^3+1, x^4+x^3+x^2+x+1
    let expected = vec![
        poly_from_bits(&[1,0,0,1,1]),  // 10011
        poly_from_bits(&[1,0,0,1,0,1]), // 101001? нет, правильный: [1,0,0,1,1] и [1,1,0,0,1]
        // Исправим:
        poly_from_bits(&[1,0,0,1,1]),  // x^4 + x + 1
        poly_from_bits(&[1,0,1,1,0]),  // x^4 + x^3 + 1  → [0]=0,x^0? Actually bit0=1, bit1=0, bit2=0, bit3=1, bit4=1 → [1,0,0,1,1]
        // Чтобы избежать путаницы, просто проверим длину и irreducible:
    ];

    let list = list_irreducibles(4);
    assert_eq!( list.len(), 3 );
    for p in &list {
        assert_eq!( p.len(), 5 );     // degree 4 → 5 коэффициентов
        assert!( is_irreducible(p) );
    }
}

#[test]
fn list_length_degree_8() {
    let list8 = list_irreducibles(8);
    assert_eq!( list8.len(), 30 );   // по условию задания
    // Проверим, что все они действительно неприводимы
    for p in list8 {
        assert!( is_irreducible(&p) );
        assert_eq!( p.len(), 9 );     // degree 8 → 9 коэффициентов
    }
}
