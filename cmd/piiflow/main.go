// Copyright 2026 The piiflow Authors
// SPDX-License-Identifier: Apache-2.0

// Command piiflow finds personal data (PII) flowing from sources to sinks
// such as logs, analytics/crash SDKs and third-party APIs.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/GoNetTools/pii-scanner/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := app.New(os.Stdout, os.Stderr).Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
