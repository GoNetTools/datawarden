// Copyright 2026 The pii-scanner Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/GoNetTools/pii-scanner/internal/config"

var initTemplates = []struct{ name, body string }{
	{config.FileName, config.Template},
	{".pii-scannerignore", ignoreTemplate},
	{".pii-scanner/rules/example.yaml", exampleRules},
}

const ignoreTemplate = `# Paths pii-scanner should not scan (gitignore syntax).
# Built-in defaults already skip node_modules/, vendor/, build/, dist/,
# binaries, images and lock files; re-include one with "!pattern".

# Generated code
# **/generated/
# *.pb.go

# Synthetic test data you have reviewed
# testdata/fake-users.json
`

const exampleRules = `# Repository rules. Same format as the built-in rules; a rule with the id of
# a built-in rule replaces it, and {id: ..., disabled: true} turns it off.

# - id: sdk.acme.telemetry
#   lang: [kotlin, java]
#   call: com.acme.telemetry.Telemetry.send
#   arg: 0
#   dest: { host: telemetry.acme.vn, kind: third_party, vendor: Acme Telemetry, region: vn }

# - id: log.go.fmt_print
#   disabled: true
`
