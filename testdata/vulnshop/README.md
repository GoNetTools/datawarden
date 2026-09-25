# vulnshop: vulnerable by design

A small online shop that leaks personal data, health data and credentials on purpose, so you can see what datawarden reports. **Do not copy this code.** All personal data and secrets in it are synthetic.

| Part | Path | Language |
|---|---|---|
| API | `backend/` | Go (stdlib + a Sentry stub, so it builds offline) |
| Checkout page | `web/src/checkout.ts` | TypeScript |
| Recommender service | `recommender/app/` | Python (Flask) |
| Android app | `android/.../checkout/CheckoutActivity.kt`, `android/.../profile/ProfileSync.java` | Kotlin, Java |
| iOS app | `ios/VulnShop/CheckoutViewModel.swift` | Swift |
| Seed data | `seed/customers.csv` | CSV |
| Deployment settings | `backend/deploy/staging.env` | env file |

In the sources, `// LEAK:` marks a planted leak and `// SAFE:` marks a look-alike that must **not** be reported. The answer key used for scoring is the `vulnshop` case in [`../eval.yaml`](../eval.yaml).

## Run it

```sh
go run ./cmd/datawarden scan testdata/vulnshop --root testdata/vulnshop --no-baseline --no-cache
go run ./cmd/datawarden map --root testdata/vulnshop --no-cache --format dpia
go run ./cmd/datawarden-bench                     # precision/recall for every labelled case
```

Or on GitHub: **Actions → demo → Run workflow**. The job summary shows the findings, the data map and the accuracy tables, and the reports are attached as an artifact.

## What is planted

| # | Leak | Where | Expected rule |
|--:|---|---|---|
| 1 | Email in the signup log | `api.Server.Signup` | `log.go.stdlib` |
| 2 | Email set as the Sentry user | `api.Server.Signup` (closure) | `sdk.go.sentry.scope` |
| 3 | Date of birth in a Sentry message | `api.Server.Signup` | `sdk.go.sentry.scope` |
| 4 | Phone number posted to an SMS vendor | `api.sendOTP` | `net.go.http_form` |
| 5 | CCCD printed three calls deep | `api.writeAudit` | `log.go.fmt_print` |
| 6 | Email in a failed-login log | `api.Server.Login` | `log.go.slog` |
| 7 | Client IP sent to a geo lookup | `api.Server.Login` | `net.go.http_get` |
| 8 | Card number wrapped into an error, then logged | `api.Server.Charge` | `log.go.stdlib` |
| 9–10 | Email and phone in a world-readable export file | `api.Server.Export` | `storage.go.file` |
| 11–12 | Email and phone printed to stdout | `api.Server.Support` | `log.go.fmt_print` |
| 13 | SHA-256 of a phone number logged (reversible) | `api.Server.Support` | `log.go.stdlib` |
| 14 | Full name logged from a goroutine | `api.Server.Welcome` | `log.go.stdlib` |
| 15 | Email set as the Sentry user | `placeOrder` | `sdk.ts.sentry.set_user` |
| 16 | Phone in a PostHog event | `placeOrder` | `sdk.ts.posthog` |
| 17 | Card number in `localStorage` | `placeOrder` | `storage.ts.web_storage` |
| 18 | Shipping address in the console | `placeOrder` | `log.ts.console` |
| 19 | Phone posted to a partner CRM | `placeOrder` | `net.ts.fetch` |
| 20 | Geolocation beaconed to an ad network | `trackStore` | `net.ts.beacon` |
| 21 | Email as the Firebase Analytics user id | `CheckoutActivity.onSignedIn` | `sdk.firebase.analytics.user_id` |
| 22 | Phone logged with Timber | `CheckoutActivity.onOtpRequested` | `log.android.timber` |
| 23 | Card number on the clipboard | `CheckoutActivity.copyCard` | `ipc.android.clipboard` |
| 24 | Device phone number (`telephony.line1Number`) logged | `CheckoutActivity.prefillPhone` | `log.android.logcat` |
| 25 | Last known location sent to Amplitude | `CheckoutActivity.trackDelivery` | `sdk.amplitude` |
| 26 | Email in an implicit broadcast | `ProfileSync.publish` | `ipc.android.broadcast` |
| 27 | Date of birth in logcat | `ProfileSync.publish` | `log.android.logcat` |
| 28–32 | Phone, email, CCCD, card and IBAN committed in seed data | `seed/customers.csv:2` | literal detectors |
| 33 | Password in a debug log | `api.Server.Login` | `log.go.stdlib` |
| 34 | Medical record number in a Sentry message | `api.Server.Refill` | `sdk.go.sentry.scope` |
| 35 | Access token in `localStorage` | `signIn` | `storage.ts.web_storage` |
| 36–37 | AWS access key id and a service JWT committed | `backend/deploy/staging.env` | `aws-access-key-id`, `jwt` value patterns |
| 38 | Email in the recommender log | `views:recommendations` | `log.py.logging` |
| 39 | Phone number as Sentry extra context | `views:recommendations` | `sdk.py.sentry` |
| 40 | Date of birth posted to an ad-tech partner | `views:recommendations` | `net.py.http` |
| 41–42 | Email and password printed by a debugging helper | `views:debug_attempt` | `log.py.print` |
| 43–45 | Whole profile (email, phone, date of birth) pickled to a world-readable file | `store:save_profile` | `storage.py.file` |
| 46 | Email as the Crashlytics user id | `CheckoutViewModel.placeOrder` | `sdk.swift.firebase.crashlytics` |
| 47 | Phone number in a Firebase Analytics event | `CheckoutViewModel.placeOrder` | `sdk.swift.firebase.analytics` |
| 48 | Card number logged with `privacy: .public` | `CheckoutViewModel.placeOrder` | `log.swift.os_log` |
| 49 | Email in UserDefaults | `CheckoutViewModel.placeOrder` | `storage.swift.user_defaults` |
| 50 | Card number on the general pasteboard | `CheckoutViewModel.copyCard` | `ipc.swift.pasteboard` |
| 51 | Email sent to a mailing vendor | `CheckoutViewModel.sendReceipt` | `net.swift.urlsession` |

Traps that must stay quiet: database inserts (first party), customer and order IDs, the nickname, a field tagged `pii:"-"`, masked email/card/phone, `len(email)`, cart sizes, a SHA-256 of the password (hashing is a safe transform for credentials), an API key in an `Authorization` header and a token sent to the API that issued it (credentials are meant for the services they unlock), the login request's response, email sent to the shop's own API (`first_party_domains` in `.datawarden.yaml`), the AWS documentation key `AKIAIOSFODNN7EXAMPLE`, the shopper id, nickname and masked email in the recommender, its own SQLite database, a unified-log message whose email is redacted by default, and the placeholder row in the CSV (`0123456789`, `test@example.com`, `4111 1111 1111 1111`).

## Known results

datawarden finds 49 of the 51 leaks with one false positive (precision 0.98, recall 0.96):

- **Missed #24:** Kotlin's property syntax `telephony.line1Number` is not matched by the source rule for `getLine1Number()`.
- **Missed #30:** the CCCD detector needs a label on the same line as the value; in a CSV the label is in the header row.
- **False positive:** `localStorage.setItem("emailOptIn", "true")` is reported as an email because of the key name. Raising `min_confidence` to 0.65 removes it without losing any leak.
