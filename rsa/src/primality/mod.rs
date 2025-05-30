pub(crate) mod fermat;
pub(crate) mod miller_rabin;
pub(crate) mod solovay_strassen;
pub use fermat::FermatTest;
pub use miller_rabin::MillerRabinTest;
pub use solovay_strassen::SolovayStrassenTest;

use num_bigint::BigUint;

/// Использует шаблонный метод
pub trait PrimalityTest {
    fn is_probably_prime(&self, n: &BigUint, confidence: f64) -> bool {
        let iterations = confidence_to_iterations(confidence, self.error_probability());
        for _ in 0..iterations {
            if !self.run_iteration(n) {
                return false;
            }
        }
        true
    }

    fn run_iteration(&self, n: &BigUint) -> bool;

    fn error_probability(&self) -> f64 {
        0.5
    }
}

fn confidence_to_iterations(confidence: f64, per_iter_error: f64) -> u32 {
    assert!(confidence >= 0.0 && confidence < 1.0,
            "confidence must be in [0,1), got {}", confidence);
    assert!(per_iter_error > 0.0 && per_iter_error < 1.0,
            "per-iteration error must be in (0,1), got {}", per_iter_error);

    let k = ((1.0 - confidence).ln() / per_iter_error.ln()).ceil() as i32;

    std::cmp::max(k, 1) as u32
}
