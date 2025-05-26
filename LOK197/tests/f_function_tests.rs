use LOK197::crypto::f_function::round_function;

#[test]
fn test_round_function_zero() {
    // f(0,0) не должно быть нулём
    assert_ne!(round_function(0u64, 0u64), 0);
}

#[test]
fn test_round_function_simple_inputs() {
    let a = round_function(1u64, 0u64);
    let b = round_function(0u64, 1u64);
    let c = round_function(1u64, 1u64);
    // хотя бы одна пара должна отличаться
    assert!(a != b || a != c || b != c);
}

#[test]
fn test_round_function_max_values() {
    // должен укладываться в u64, но не паниковать
    let _ = round_function(u64::MAX, u64::MAX);
}

#[test]
fn test_round_function_random_consistency() {
    let input = 0x1234_5678_9ABC_DEF0;
    let key   = 0xA5A5_A5A5_DEAD_BEEF;
    assert_eq!(round_function(input, key), round_function(input, key));
}

#[test]
fn test_round_function_symmetry() {
    let a = 0xCAFEBABE_DEADC0DE;
    let b = 0xDEADBEEF_12345678;
    assert_ne!(
        round_function(a, b),
        round_function(b, a),
        "f(a,b) не симметрична"
    );
}
