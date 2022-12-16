package cataloger

import "github.com/anchore/syft/syft/source"

// Deprecated: will be removed in syft v1.0.0
type SearchConfig struct {
	IncludeIndexedArchives   bool
	IncludeUnindexedArchives bool
	Scope                    source.Scope
}

// Deprecated: will be removed in syft v1.0.0
func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
		Scope:                    source.SquashedScope,
	}
}
