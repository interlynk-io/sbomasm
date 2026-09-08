// Copyright 2025 Interlynk.io and Contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// Reproduces interlynk-io/sbomasm#185: subcommands run without their
// required positional argument print only the bare cobra error
// ("accepts 1 arg(s), received 0") and no usage/flags block, because
// SilenceUsage is set to true on the subcommand. This test invokes the
// real rootCmd (as main.main() does) exactly the way the issue reporter
// did: `sbomasm edit` with no input file.
func TestEditMissingArgShowsUsage(t *testing.T) {
	var buf bytes.Buffer
	rootCmd.SetOut(&buf)
	rootCmd.SetErr(&buf)
	rootCmd.SetArgs([]string{"edit"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("expected an error when required positional arg is missing")
	}

	out := buf.String()
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("expected usage/help text to be shown when required arg is missing, got only:\n%s", out)
	}
	if !strings.Contains(out, "--subject") {
		t.Fatalf("expected flag list (e.g. --subject) to be shown when required arg is missing, got only:\n%s", out)
	}
}
