//! Robust statistical functions (P0 - Outlier-resistant math)
pub fn median(values: &[f32]) -> f32 {
    if values.is_empty() { return 0.0; }
    let mid = values.len() / 2;
    if values.len() % 2 == 0 { (values[mid - 1] + values[mid]) / 2.0 }
    else { values[mid] }
}
pub fn mad(values: &[f32]) -> f32 {
    if values.is_empty() { return 0.0; }
    let median_val = median(values);
    let mut devs: Vec<f32> = values.iter().map(|v| (v - median_val).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    median(&devs)
}
pub fn deviation(values: &[f32]) -> f32 {
    if values.is_empty() { return 0.0; }
    let med = median(values);
    let sum: f32 = values.iter().map(|v| (v - med).abs()).sum();
    sum / values.len() as f32
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_median_odd() { assert_eq!(median(&[100.0, 200.0, 300.0, 400.0, 500.0]), 300.0); }
    #[test]
    fn test_mad_basic() { let v = vec![100.0, 200.0, 300.0, 400.0, 500.0]; assert_eq!(mad(&v), 100.0); }
    #[test]
    fn test_outlier() { let mut v = vec![100.0; 99]; v.push(7000.0); assert_eq!(median(&v), 100.0); assert!(mad(&v) < 50.0); }
}
