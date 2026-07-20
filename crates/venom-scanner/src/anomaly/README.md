# Anomaly Detection Module

## Architecture
- **statistics.rs**: Median/MAD (P0 outlier-resistant math)
- **confidence.rs**: Multi-signal confidence metrics (P1)
- **rules.rs**: Flexible status/error rules (P1)

## Key Features
✅ P0: Median + MAD (5-10x more robust than mean/stddev)
✅ P1: Exponential confidence scoring
✅ P1: Flexible error keyword and status code matching

## Testing
```bash
cargo test --lib anomaly
```
