# Scenario test data

The same 26 scenarios written in every supported language, from a value
logged on the line it arrives to a value that crosses several functions,
objects and callbacks before it leaves the program. Each scenario uses
synthetic data only.

Every scenario line carries the annotations `datawarden rules test` checks:

```
// ruleid: <rule>   the next line must produce a finding for <rule>
// ok: <rule>       the next line must not produce a violation for <rule>
```

(`#` comments in Python.) A `ruleid:` line only needs a finding: flows that
the default policy accepts (first-party storage, a consent-guarded call)
still carry `ruleid:`.

## Running

```sh
datawarden rules test testdata/scenarios/go
datawarden rules test testdata/scenarios/python
datawarden rules test testdata/scenarios/java
datawarden rules test testdata/scenarios/kotlin
datawarden rules test testdata/scenarios/swift
datawarden rules test testdata/scenarios/typescript
```

The Go directory is its own module (standard library only). The committed
values in `literals/` are not annotated: `literals/expected.yaml` lists what
`datawarden scan --literals-only testdata/scenarios/literals` should report.

## Scenarios

| # | Level | Scenario | Data | Sink | Expected |
|---|---|---|---|---|---|
| S01 | 1 basic | parameter logged | email | log | finding |
| S02 | 1 basic | local variable logged | phone | log | finding |
| S03 | 1 basic | non-personal values and look-alike names | order id, counts, flags | log | ok |
| S04 | 1 basic | credential logged | password | log | finding |
| S05 | 1 basic | masked before logging | email | log | ok |
| S06 | 1 basic | hashed personal data (re-identifiable) | email | log | finding |
| S07 | 1 basic | hashed credential | password | log | ok |
| S08 | 2 intermediate | string formatting | health (diagnosis) | log | finding |
| S09 | 2 intermediate | object field | card number | storage | finding |
| S10 | 2 intermediate | map key labels the value | SSN | network | finding |
| S11 | 2 intermediate | helper function (interprocedural) | email | log | finding |
| S12 | 2 intermediate | getter return value | medical record number | log / crash reporter | finding |
| S13 | 2 intermediate | overwritten before the sink | email | log | ok on the constant path |
| S14 | 2 intermediate | credential sent to the service it unlocks | API key | network | ok |
| S15 | 3 advanced | collection built in a loop | email | log | finding |
| S16 | 3 advanced | closure capturing the value | phone | log | finding |
| S17 | 3 advanced | error / exception message | email | log | finding |
| S18 | 3 advanced | consent-guarded analytics | email | third party / network | finding (reported with its guard) |
| S19 | 3 advanced | sanitizer check (`isMasked`) | email | log | ok |
| S20 | 3 advanced | constructor stores, another method logs | access token | log | finding |
| S21 | 4 complex | interface / dynamic dispatch | phone | log | finding in the implementation |
| S22 | 4 complex | callback kept in a field, run later | email | log | finding |
| S23 | 4 complex | value three fields deep | home address | network | finding |
| S24 | 4 complex | request → service → repository → partner | date of birth | storage + network | findings |
| S25 | 4 complex | session token persisted on the device | session token | storage | finding |
| S26 | 4 complex | object logged before data is added | email | log | ok, then finding |

Language notes:

- **Swift:** `Logger` and `os_log` redact interpolated values unless they
  are marked `.public`, so S01 also has an `ok:` redacted line.
- **Go:** there is no analytics SDK in the standard library, so S18 sends to
  an analytics endpoint over `net/http`, and S12 logs through `log/slog`.
- **Java:** S24's repository writes through JDBC, which has no sink rule, so
  only the partner call is annotated there.
- **Swift / TypeScript:** S24 stores the date of birth in `UserDefaults` /
  `sessionStorage` instead of a database.
- **Per language sinks:** logs use slf4j (Java), `android.util.Log`
  (Kotlin), `print` / `Logger` (Swift), `console` (TypeScript), `logging`
  (Python) and `log` (Go); crash reporting uses Sentry, analytics Segment or
  Firebase, network the usual HTTP client of each ecosystem.

## Committed values (`literals/`)

| Level | File | What it exercises |
|---|---|---|
| 1 | `level1_customers.csv` | card, IBAN, SSN and email in plain columns, next to placeholder rows |
| 2 | `level2_seed.json`, `level2_config.yaml` | values nested in JSON, a contact and a QA SSN in YAML config, a documented test card |
| 3 | `level3_fixtures.sql` | separators inside card numbers, grouped IBANs, and look-alikes: failed Luhn, wrong IBAN checksum, reserved SSN ranges |
| 4 | `level4_notes.md` | values inside prose, next to UUIDs, versions, timestamps, digit runs and role addresses |

All card numbers pass Luhn, all IBANs pass mod-97 and all SSNs are
structurally valid, but none belong to anyone.
