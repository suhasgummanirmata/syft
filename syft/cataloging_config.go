package syft

import (
	"crypto"
	"github.com/anchore/syft/syft/file/cataloger/filecontents"
	"github.com/anchore/syft/syft/file/cataloger/secrets"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type CatalogingConfig struct {
	// tool-specific information
	ToolName          string
	ToolVersion       string
	ToolConfiguration interface{}
	// applies to all catalogers
	Scope                source.Scope
	ProcessTasksInSerial bool
	// package
	PackageCatalogers []pkg.Cataloger
	// file metadata
	CaptureFileMetadata bool
	DigestHashes        []crypto.Hash
	// secrets
	CaptureSecrets bool
	SecretsConfig  secrets.CatalogerConfig
	SecretsScope   source.Scope
	// file classification
	ClassifyFiles   bool
	FileClassifiers []file.Classifier
	// file contents
	ContentsConfig filecontents.CatalogerConfig
}

func DefaultCatalogingConfig() CatalogingConfig {
	return CatalogingConfig{
		Scope:           source.SquashedScope,
		ToolName:        internal.ApplicationName,
		ToolVersion:     version.Guess(),
		SecretsScope:    source.AllLayersScope,
		SecretsConfig:   secrets.DefaultCatalogerConfig(),
		FileClassifiers: file.DefaultClassifiers(),
		ContentsConfig:  filecontents.DefaultCatalogerConfig(),
	}
}
