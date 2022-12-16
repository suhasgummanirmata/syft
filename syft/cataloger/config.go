package cataloger

import (
	"crypto"

	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/source"
)

const (
	NoFilesSelection    FileCatalogingSelection = "no-files"
	OwnedFilesSelection FileCatalogingSelection = "owned-files"
	AllFilesSelection   FileCatalogingSelection = "all-files"
)

type FileCatalogingSelection string

type Config struct {
	Search                  SearchConfig
	Relationships           RelationshipsConfig
	SyntheticData           SyntheticConfig
	FileCatalogingSelection FileCatalogingSelection
	FileHashers             []crypto.Hash
}

type RelationshipsConfig struct {
	FileOwnership        bool
	FileOwnershipOverlap bool
}

type SyntheticConfig struct {
	GenerateCPEs          bool
	GuessLanguageFromPURL bool
}

type SearchConfig struct {
	IncludeIndexedArchives   bool
	IncludeUnindexedArchives bool
	Scope                    source.Scope
}

func DefaultConfig() Config {
	return Config{
		Search:                  DefaultSearchConfig(),
		Relationships:           DefaultRelationshipsConfig(),
		SyntheticData:           DefaultSyntheticConfig(),
		FileCatalogingSelection: OwnedFilesSelection,
	}
}

func DefaultSearchConfig() SearchConfig {
	return SearchConfig{
		IncludeIndexedArchives:   true,
		IncludeUnindexedArchives: false,
		Scope:                    source.SquashedScope,
	}
}

func DefaultSyntheticConfig() SyntheticConfig {
	return SyntheticConfig{
		GenerateCPEs:          true,
		GuessLanguageFromPURL: true,
	}
}

func DefaultRelationshipsConfig() RelationshipsConfig {
	return RelationshipsConfig{
		FileOwnership:        true,
		FileOwnershipOverlap: true,
	}
}

func (c Config) Java() java.Config {
	return java.Config{
		SearchUnindexedArchives: c.Search.IncludeUnindexedArchives,
		SearchIndexedArchives:   c.Search.IncludeIndexedArchives,
	}
}
