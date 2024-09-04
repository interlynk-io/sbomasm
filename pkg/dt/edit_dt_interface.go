package dt

import (
	"context"
	"fmt"
	"os"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/logger"
)

type EditParams struct {
	Url        string
	ApiKey     string
	ProjectIds uuid.UUID

	Ctx *context.Context

	Input  string
	Output string

	Subject string
	Search  string

	Append  bool
	Missing bool

	Name        string
	Version     string
	Supplier    string
	Timestamp   bool
	Authors     []string
	Purl        string
	Cpe         string
	Licenses    []string
	Hashes      []string
	Tools       []string
	CopyRight   string
	Lifecycles  []string
	Description string
	Repository  string
	Type        string
}

func NewEditParams() *EditParams {
	return &EditParams{}
}

func (etP *EditParams) PopulateInputField(ctx context.Context) {
	log := logger.FromContext(ctx)

	log.Debugf("Config: %+v", etP)

	dTrackClient, err := dtrack.NewClient(etP.Url,
		dtrack.WithAPIKey(etP.ApiKey), dtrack.WithDebug(false))
	if err != nil {
		log.Fatalf("Failed to create Dependency-Track client: %s", err)
	}
	fmt.Println("dtP.ProjectIds: ", etP.ProjectIds)

	log.Debugf("Processing project %s", etP.ProjectIds)

	prj, err := dTrackClient.Project.Get(ctx, etP.ProjectIds)
	if err != nil {
		log.Fatalf("Failed to get project: %s", err)
	}
	fmt.Printf("ID: %s, Name: %s, Version: %s", prj.UUID, prj.Name, prj.Version)
	fmt.Println()

	bom, err := dTrackClient.BOM.ExportProject(ctx, etP.ProjectIds, dtrack.BOMFormatJSON, dtrack.BOMVariantInventory)
	if err != nil {
		log.Fatalf("Failed to export project: %s", err)
	}
	fmt.Println("bom: ", bom)

	fname := fmt.Sprintf("tmpfile-%s", etP.ProjectIds)
	f, err := os.CreateTemp("", fname)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	// defer os.Remove(f.Name())
	fmt.Println("f.Name(): ", f.Name())

	f.WriteString(bom)
	etP.Input = f.Name()
}
