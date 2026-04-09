package gsbom

import (
	"context"
	"fmt"
	"os"

	"go.yaml.in/yaml/v2"
)

type GenerateSBOMParams struct {
	Ctx *context.Context

	ConfigPath  string
	InputFiles  []string
	Output      string
	Tags        []string
	ExcludeTags []string
	Format      string
	RecursePath string
	Filename    string
}

func NewGenerateSBOMParams() *GenerateSBOMParams {
	return &GenerateSBOMParams{}
}

type Artifact struct {
	Name           string
	Version        string
	Description    string
	PrimaryPurpose string

	Supplier Supplier
	Authors  []Author

	LicenseID string
	PURL      string
	CPE       string

	Copyright string
}

type Author struct {
	Name  string
	Email string
}

type Supplier struct {
	Name  string
	Email string
}

type artifactYAML struct {
	App struct {
		Name           string `yaml:"name"`
		Version        string `yaml:"version"`
		Description    string `yaml:"description"`
		PrimaryPurpose string `yaml:"primary_purpose"`
		Purl           string `yaml:"purl"`
		CPE            string `yaml:"cpe"`

		License struct {
			ID string `yaml:"id"`
		} `yaml:"license"`

		Supplier struct {
			Name  string `yaml:"name"`
			Email string `yaml:"email"`
		} `yaml:"supplier"`

		Author []struct {
			Name  string `yaml:"name"`
			Email string `yaml:"email"`
		} `yaml:"author"`

		Copyright string `yaml:"copyright"`
	} `yaml:"app"`
}

func LoadArtifactConfig(path string) (*Artifact, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg artifactYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	// Validation
	if cfg.App.Name == "" {
		return nil, fmt.Errorf("artifact name is required")
	}
	if cfg.App.Version == "" {
		return nil, fmt.Errorf("artifact version is required")
	}

	if cfg.App.PrimaryPurpose == "" {
		return nil, fmt.Errorf("artifact primary purpose is required")
	}

	artifact := &Artifact{
		Name:           cfg.App.Name,
		Version:        cfg.App.Version,
		Description:    cfg.App.Description,
		PrimaryPurpose: cfg.App.PrimaryPurpose,

		Supplier: Supplier{
			Name:  cfg.App.Supplier.Name,
			Email: cfg.App.Supplier.Email,
		},

		Authors: func() []Author {
			authors := make([]Author, len(cfg.App.Author))
			for i, a := range cfg.App.Author {
				authors[i] = Author{
					Name:  a.Name,
					Email: a.Email,
				}
			}
			return authors
		}(),

		LicenseID: cfg.App.License.ID,
		PURL:      cfg.App.Purl,
		CPE:       cfg.App.CPE,
		Copyright: cfg.App.Copyright,
	}

	return artifact, nil
}
