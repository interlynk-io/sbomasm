package assemble

import (
	"context"
	"fmt"
	"testing"

	"github.com/interlynk-io/sbomasm/pkg/logger"
	"github.com/stretchr/testify/assert"
)

func TestAssemble(t *testing.T) {
	// Initialize mock assemble parameters
	assembleParams := &Params{
		Name:    "vivek",
		Version: "1.0.0",
		Type:    "application",
		Input:   []string{"../../samples/cdx/sbomex-cdx.json", "../../samples/cdx/sbomgr-cdx.json"},
		Output:  "updated1.cyclonedx.json",
	}
	ctx := logger.WithLogger(context.Background())
	assembleParams.Ctx = &ctx

	// Check if logger is properly initialized
	if assembleParams.Ctx == nil {
		fmt.Println("Logger context is not initialized")
		t.Fatal("Logger context is not initialized")
	}

	// Populate the config object
	mockConfig, err := PopulateConfig(assembleParams)
	assert.NoError(t, err)

	// Check if mockConfig is properly initialized
	if mockConfig == nil {
		t.Fatal("mockConfig is not initialized")
	}

	// Call the Assemble function
	err = Assemble(mockConfig)

	// Assert no error occurred
	assert.NoError(t, err, "Error assembling")

	// Add more assertions as needed to verify the behavior
}
