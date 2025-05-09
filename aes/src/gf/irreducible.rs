use super::arithmetic::Poly;

/// Проверка: является ли полином неприводимым над GF(2)
pub fn is_irreducible(poly: &Poly) -> bool {
    todo!("Проверка неприводимости через критерий Рабина")
}

/// Генерация всех неприводимых полиномов степени `n`
pub fn list_irreducibles(n: usize) -> Vec<Poly> {
    todo!("Перебор всех полиномов степени n и фильтрация по is_irreducible")
}
