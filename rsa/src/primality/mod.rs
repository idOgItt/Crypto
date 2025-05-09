pub(crate) mod fermat;
pub(crate) mod miller_rabin;
pub(crate) mod solovay_strassen;
pub use fermat::FermatTest;
pub use miller_rabin::MillerRabinTest;
pub use solovay_strassen::SolovayStrassenTest;

use num_bigint::BigUint;

/// Интерфейс для вероятностного теста простоты.
/// Использует шаблонный метод: фиксированный public API, переопределяется одна итерация.
pub trait PrimalityTest {
    /// Основной метод: возвращает true, если n — вероятно простое с заданной вероятностью
    fn is_probably_prime(&self, n: &BigUint, confidence: f64) -> bool {
        let iterations = confidence_to_iterations(confidence);
        for _ in 0..iterations {
            if !self.run_iteration(n) {
                return false;
            }
        }
        true
    }

    /// Одна итерация теста — реализуется в подклассах
    fn run_iteration(&self, n: &BigUint) -> bool;
}
fn confidence_to_iterations(confidence: f64) -> u32 {
    // Пример: вероятность ошибки каждой итерации 1/2,
    // тогда confidence = 1 - (1/2)^k  =>  k = log2(1 / (1 - confidence))
    ((1.0 / (1.0 - confidence)).log2().ceil()) as u32
}
