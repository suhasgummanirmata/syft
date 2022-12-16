package cataloger

import (
	"github.com/anchore/syft/syft/pkg/cataloger/java"
)

// Deprecated: will be removed in syft v1.0.0
type Config struct {
	Search     SearchConfig
	Catalogers []string
}

// Deprecated: will be removed in syft v1.0.0
func DefaultConfig() Config {
	return Config{
		Search: DefaultSearchConfig(),
	}
}

// Deprecated: will be removed in syft v1.0.0
func (c Config) Java() java.Config {
	return java.Config{
		SearchUnindexedArchives: c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.Search.IncludeIndexedArchives,
	}
}
