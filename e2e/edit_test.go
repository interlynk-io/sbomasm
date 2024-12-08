package e2e_edit_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/interlynk-io/sbomasm/cmd"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestSbomasmEdit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	t.Parallel()
	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/edit",
		RequireExplicitExec: true,
		Setup: func(env *testscript.Env) error {
			// copy required files to the workspace
			if err := copyFile("testdata/edit/photon-lite.spdx.json", filepath.Join(env.WorkDir, "photon-lite.spdx.json")); err != nil {
				return err
			}
			if err := copyFile("testdata/edit/expected-output-lite.spdx.json", filepath.Join(env.WorkDir, "expected-output-lite.spdx.json")); err != nil {
				return err
			}

			return nil
		},
	})
}

func runSbomasm() int {
	cmd.Execute()
	return 0
}

func TestMain(m *testing.M) {
	exitCode := testscript.RunMain(m, map[string]func() int{
		"sbomasm": runSbomasm,
	})
	os.Exit(exitCode)
}

// Helper function to copy files
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
