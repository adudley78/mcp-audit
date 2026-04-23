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
- **SARIF** — when `result.score` is present, `run.properties` includes
  `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`,
  and `mcp-audit/deductions`. When `--no-score` is passed, `cli.py` nulls
  the score before formatting, so the properties block is omitted.
- **Nucleus** — score data is not currently embedded in FlexConnect output
  (blocked on Swagger spec validation).

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

## Scoring and Severity Filtering

The scan score is always computed from the **complete finding set** before
`--severity-threshold` filtering is applied. This means the score and grade
in JSON and SARIF output reflect all findings regardless of the threshold
you set. Exit code and `has_findings` reflect only findings at or above the
threshold.

**Example:** a scan with two MEDIUM findings and `--severity-threshold HIGH`
will produce exit code 0 and an empty terminal findings list, but the JSON
output will still show a score of 98/100 (−2 for two MEDIUM findings). The
grade badge in SARIF will still read `B`.

This is intentional — the score is a property of the configuration, not of
your alerting threshold. Suppressing findings for operational noise reduction
should not mask the underlying security posture.

If you want to exclude findings from the score entirely, use
`--severity-threshold` in combination with reviewing only the relevant output
format; the JSON `score` field always represents the full picture.

## Known Limitations

- Scoring weights are hardcoded and not yet user-configurable. Custom weights
  are planned via the policy-as-code engine.
- INFO findings produce a −1 deduction entry even when positive bonuses push the
  final score to 100. The deduction is a correct signal — a clean scan with
  informational notes is still achievable as 100/A. See GAPS.md for detail.
