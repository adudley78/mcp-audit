# Scan Score Methodology

mcp-audit assigns every scan a letter grade (A–F) and numeric score (0–100)
based on the findings produced.

## Scoring Algorithm

Start at 100 points. Deduct points per finding by severity:

| Severity | Deduction per finding |
|----------|-----------------------|
| CRITICAL | −25 |
| HIGH     | −15 |
| MEDIUM   | −8  |
| LOW      | −3  |
| INFO     | −1  |

Score is floored at 0 before bonuses are applied.

## Positive Signal Bonuses (capped at +10 total)

| Signal | Bonus | Condition |
|--------|-------|-----------|
| No credential exposure | +3 | No findings from the `credentials` analyzer |
| No high-severity issues | +5 | No CRITICAL or HIGH findings |
| No prompt injection risks | +2 | No findings from the `poisoning` analyzer |

Final score is capped at 100.

## Grade Thresholds

| Grade | Score Range |
|-------|-------------|
| A     | 90–100      |
| B     | 75–89       |
| C     | 60–74       |
| D     | 40–59       |
| F     | 0–39        |

## Output locations

- **Terminal** — a colour-coded grade panel is printed after findings by default.
  Grades A/B are green, C/D are yellow, F is red.
- **JSON** — `ScanResult.score` is a nested `ScanScore` object containing
  `numeric_score`, `grade`, `positive_signals` (list of strings), and
  `deductions` (list of strings).
- **HTML dashboard** — a colour-coded grade badge appears in the report header.
- **SARIF / Nucleus** — score data is not currently embedded in these formats.

## Suppressing the Score

Pass `--no-score` to any `scan` invocation to suppress the grade panel in
terminal output. The score is still calculated and included in JSON and HTML
output regardless.

```
mcp-audit scan --no-score
```

## Implementation

`scoring.py` — `calculate_score(findings) -> ScanScore`

The scorer is called once, after all analyzers have completed, inside
`scanner.py`. Analyzers never call the scorer directly. `ScanScore` is a
Pydantic model defined in `models.py`.

## Known Limitations

- Scoring weights are hardcoded and not yet user-configurable. Custom weights
  are a planned Pro feature (policy-as-code engine).
- INFO findings produce a −1 deduction entry even when positive bonuses push the
  final score to 100. The deduction is a correct signal — a clean scan with
  informational notes is still achievable as 100/A. See GAPS.md for detail.
