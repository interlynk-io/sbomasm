package types

// pkg/rm/types/params.go

type RemovalKind string

const (
	FieldRemoval      RemovalKind = "field"
	ComponentRemoval  RemovalKind = "component"
	DependencyRemoval RemovalKind = "dependency"
)

type RmParams struct {
	Kind             RemovalKind
	Field            string
	Scope            string
	Key              string
	Value            string
	All              bool
	ComponentName    string
	ComponentVersion string
	DependencyID     string
	IsComponent      bool
	IsDependency     bool
	DryRun           bool
	Summary          bool
}
