package pkg

import "github.com/anchore/syft/syft/artifact"

// TODO: as more relationships are added, this function signature will probably accommodate selection
// Deprecated: this type is deprecated and will be removed in a future release.
func NewRelationships(catalog *Catalog) []artifact.Relationship {
	return RelationshipsByFileOwnershipOverlap(catalog)
}
