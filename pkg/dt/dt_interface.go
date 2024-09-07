package dt

import (
	"context"
	"fmt"
	"os"

	dtrack "github.com/DependencyTrack/client-go"
	"github.com/google/uuid"
	"github.com/interlynk-io/sbomasm/pkg/logger"
)

type Params struct {
	Url             string
	ApiKey          string
	ProjectIds      []uuid.UUID
	UploadProjectID uuid.UUID

	Ctx    *context.Context
	Input  []string
	Output string
	Upload bool

	Name    string
	Version string
	Type    string

	FlatMerge     bool
	HierMerge     bool
	AssemblyMerge bool

	Xml  bool
	Json bool

	OutputSpec        string
	OutputSpecVersion string
}

func NewParams() *Params {
	return &Params{}
}

func (dtP *Params) PopulateInputField(ctx context.Context) {
	log := logger.FromContext(ctx)

	log.Debugf("Config: %+v", dtP)

	dTrackClient, err := dtrack.NewClient(dtP.Url,
		dtrack.WithAPIKey(dtP.ApiKey), dtrack.WithDebug(false))
	if err != nil {
		log.Fatalf("Failed to create Dependency-Track client: %s", err)
	}

	for _, pid := range dtP.ProjectIds {
		log.Debugf("Processing project %s", pid)

		prj, err := dTrackClient.Project.Get(ctx, pid)
		if err != nil {
			log.Fatalf("Failed to get project: %s", err)
		}
		fmt.Printf("ID: %s, Name: %s, Version: %s", prj.UUID, prj.Name, prj.Version)
		fmt.Println()

		bom, err := dTrackClient.BOM.ExportProject(ctx, pid, dtrack.BOMFormatJSON, dtrack.BOMVariantInventory)
		if err != nil {
			log.Fatalf("Failed to export project: %s", err)
		}

		fname := fmt.Sprintf("tmpfile-%s", pid)
		f, err := os.CreateTemp("", fname)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		f.WriteString(bom)
		dtP.Input = append(dtP.Input, f.Name())
	}
}
