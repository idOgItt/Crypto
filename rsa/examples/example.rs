use num_bigint::BigUint;
use num_traits::FromPrimitive;

// импортируем RsaService, а не только генератор
use rsa::rsa::{PrimalityType, RsaService};
use rsa::attacks::{FermatAttack, WienerAttack};

fn main() {
    let rsa = RsaService::new(
        PrimalityType::MillerRabin,
        0.99,     
        128,      
    );

    let (n, e) = rsa.public_key();
    let (_n, d) = rsa.private_key();
    println!("Сгенерирован ключ:\n  n = {}\n  e = {}\n  d = {}", n, e, d);

    let msg = BigUint::from_u64(42).unwrap();
    let c   = rsa.encrypt(&msg);
    let m   = rsa.decrypt(&c);
    assert_eq!(m, msg);
    println!("Шифрование→дешифрование успешно: {msg} → {c} → {m}");

    // 1) Атака Винера
    if let Some(res) = WienerAttack::attack(&n, &e) {
        println!("WienerAttack Succeeded:");
        println!("  recovered d = {}", res.d);
        println!("  φ(n) = {}", res.phi_n);
        println!("  all candidates: {:?}",
                 res.candidates.iter().map(|t| t.d.clone()).collect::<Vec<_>>()
        );
    } else {
        println!("WienerAttack failed (ключ не уязвим к Винеру)");
    }

    //2) Атака Ферма
    println!("Ferma attack now:");
    if let Some(res) = FermatAttack::attack(&n, &e) {
        println!("FermatAttack Succeeded:");
        println!("  p={}, q={}, phi={}", res.p, res.q, res.phi_n);
        println!("  recovered d = {}", res.d);
    } else {
        println!("FermatAttack failed (ключ не уязвим к Ферма)");
    }
    
}
