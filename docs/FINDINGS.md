# Reading and triaging findings

This guide is for the person who just ran `datawarden scan` on a codebase for the first time and has a list of findings to work through. It covers what a finding says, how to decide whether it is real, how to fix it, and how to silence it when it is not, in the order you should reach for them.

## What a finding says

```
NEW      high   phone → Sentry / sentry.io (third-party)  [sdk.ts.sentry.set_user]
         source  src/api/user.ts:22:32  field User.phoneNumber (field name phoneNumber)
         sink    src/lib/mask.ts:10:3  @sentry/react.addBreadcrumb  in src/lib/mask:logInfo
         path    src/api/user.ts:22 → src/lib/mask.ts:8 → :10
         confidence 0.90
```

| Part | Meaning |
|---|---|
| `NEW` | Status. `NEW` fails the build. `BASELINE` is in the baseline, `ALLOWED` is accepted by the policy (a safe transform, a consent guard, or a `policy.allow` entry; the reason follows), and `INFO` does not count (a destination kind not in `fail_on`, a first-party host, below `min_confidence`). Only `NEW` is shown unless you pass `--all`. |
| `high` | Severity, from the data type (sensitive categories such as health data, national IDs and credentials are high) and the destination. |
| `phone → Sentry / sentry.io (third-party)` | What data reaches which destination. The destination kind (`third_party`, `log`, `network`, `storage`, `ipc`, `first_party`) is what `policy.fail_on` matches. |
| `[sdk.ts.sentry.set_user]` | The sink rule that matched. `datawarden rules --kind sink` lists them; a repository rule with the same id replaces it. |
| `source` | Where the value became personal data, and **why datawarden thinks so**: `identifier "email"` (a name), `field User.phoneNumber (field name phoneNumber)` (a field name or a schema hint), `key "ssn"` (a string key next to the value), `call navigator.geolocation.getCurrentPosition` (a source API), `value of type Customer` (an object whose type has personal fields). |
| `sink` | The call that sends the data, and the function it is in. |
| `path` | The lines the value passes through, across files. `--call-graph` shows the same path as the functions it goes through, and who calls the function where it enters. |
| `confidence` | How sure the analysis is, from 0 to 1. Names are weaker than schema hints, which are weaker than source APIs, and each step through unknown code lowers it. `policy.min_confidence` (0.55 by default) is the threshold for a violation. |
| `transforms`, `guarded by` | What was applied to the value on the way (`masked`, `sha256`, ...), and the consent checks the sink runs behind. |

Committed values (literals) are shorter: the data type, the file and line, a masked form of the value and the detector that found it.

To look at many findings at once, `datawarden graph -o flows.svg` draws them as one picture, and `--function REGEXP` or `--data-type T` narrow it to one area.

## Is it real?

Answer three questions, in this order. The first "no" means it is not a leak.

1. **Is the source really that data?** Read the source description. A name can mislead: `phone` in `phoneLayoutBreakpoint` is excluded, but a project-specific name may not be. A field that holds a username is `person_name` to datawarden; whether a username is personal data in your product is your call.
2. **Does the value that reaches the sink still hold it?** Follow the path. The usual false positives are here: data put into a framework object (a request context, a service handle) and a *different* part of that object logged later, or the result of a library call the analysis cannot see into, which it assumes carries its arguments. `datawarden ir --func <function> <file>` prints exactly what the analysis read for a function.
3. **Is the destination a problem?** Logging an email in an admin command that prints it for the operator may be intended. Sending it to your own backend is `first_party` once its host is in `first_party_domains`. Sending it to an analytics SDK almost never is intended.

When the answer is "yes, yes, yes", fix the code. Otherwise, pick the narrowest silencing option below.

## Fixing a real leak

- **Don't send it.** Most log lines only need an ID: log `user.id`, not `user`. Most analytics events only need a pseudonymous ID set once.
- **Mask or redact it on the way.** A call whose name says what it does is recognised: `mask`, `redact`, `scrub`, `anonymize`, `tokenize`, `encrypt` (`maskPhone(p)`, `redactEmail(e)`). So are the library calls in the built-in transform rules (`datawarden rules --kind transform`). Masked, redacted, encrypted, tokenized and anonymized values are acceptable by default (`policy.safe_transforms`). **Hashing is not** for personal data: phone numbers and ID numbers are few enough that their hashes can be reversed. For credentials, hashing is the point and is accepted.
- **Put it behind consent.** A sink that runs only after a consent check (`if (consents.analytics) track(...)`) is reported with the check as its guard; `policy.consent_guarded: [third_party]` accepts such flows.
- **Remove committed values.** Delete real personal data from fixtures and seed files and replace it with synthetic data (`@example.com` emails, test card numbers). Rotate a committed key before deleting it: it is in the history.

## Silencing a finding that is not a leak

From narrowest to broadest. Prefer the ones near the top: they say *why*, and they don't hide the next real leak in the same place.

| When | Do this |
|---|---|
| A field is named like personal data but is not | Say so where it is declared: `pii:"-"` in a Go struct tag, `@PII("-")` on a Java or Kotlin field. |
| A field holds personal data its name does not reveal | The other way round: `pii:"email"`, `@PII("email")`, `// pii: email`. |
| Data going to one vendor or host is covered by an agreement | A `policy.allow` entry with a reason: `{sink: sdk.sentry.set_user, data_types: [email], reason: "DPA with Sentry, EU region"}`, or `{dest_host: api.partner.example}`. |
| A directory is out of scope (generated code, vendored SDK, a legacy module you have decided to live with) | `policy.allow: [{path: "legacy/**", reason: "..."}]` accepts its flows; `.datawardenignore` skips its files entirely. |
| Your backend's own hosts | `first_party_domains: [api.example.com]`: flows to them become `first_party`, which `fail_on` does not list by default. |
| A sink rule is wrong for your codebase | A repository rule file (`.datawarden/rules/`) with the same `id` to change it, or `{id: <id>, disabled: true}` to turn it off. |
| A whole data type or class is handled elsewhere | `policy.ignore_data_types: [ip_address]`, or `ignore_classes: [credential]` when a secret scanner already covers credentials. |
| Anything that exists today and will be fixed over time | `datawarden baseline`: every current violation is recorded and only new ones fail the build. |

## A first rollout

1. `datawarden init`, then `datawarden scan .` and skim the findings by rule and data type (`--format json` and `jq`, or `datawarden graph`).
2. Fix the handful that are obviously real, and add schema hints, `allow` entries or `first_party_domains` for the patterns that are obviously not.
3. `datawarden baseline`, commit `.datawarden/baseline.json`, and add datawarden to CI in PR mode (`scan --diff origin/main`). From then on, only findings a pull request introduces fail it, and they are few enough to read.
4. Work through the baseline over time; `datawarden scan --no-baseline` shows everything again.

## Telling us about a false positive

If a false positive comes from the analysis rather than from naming or policy, it is worth reporting: every false-positive pattern found on real code so far has turned into a fix and a regression test. Use the *false positive* issue template with a few lines of **made-up** code that reproduce it, the finding as datawarden printed it (values are already masked), and, if you can, the `datawarden ir` output for the function involved.
