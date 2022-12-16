package eventloop

import (
	"crypto"
	"fmt"

	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// Deprecated: will be removed in syft 1.0
type Task func(*sbom.Artifacts, *source.Source) ([]artifact.Relationship, error)

// Deprecated: will be removed in syft 1.0
func Tasks(app *config.Application) ([]Task, error) {
	var tasks []Task

	generators := []func(app *config.Application) (Task, error){
		generateCatalogPackagesTask,
		generateCatalogFileMetadataTask,
		generateCatalogFileDigestsTask,
		generateCatalogSecretsTask,
		generateCatalogContentsTask,
	}

	for _, generator := range generators {
		task, err := generator(app)
		if err != nil {
			return nil, err
		}

		if task != nil {
			tasks = append(tasks, task)
		}
	}

	return tasks, nil
}

// Deprecated: will be removed in syft 1.0
func generateCatalogPackagesTask(app *config.Application) (Task, error) {
	if !app.Package.Cataloger.Enabled {
		return nil, nil
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		cfg := cataloger.Config{
			Search: cataloger.SearchConfig{
				IncludeIndexedArchives:   app.Package.SearchIndexedArchives,
				IncludeUnindexedArchives: app.Package.SearchUnindexedArchives,
				Scope:                    app.Package.Cataloger.ScopeOpt,
			},
			Catalogers: app.Catalogers,
		}
		packageCatalog, relationships, theDistro, err := syft.CatalogPackages(src, cfg)
		if err != nil {
			return nil, err
		}

		results.PackageCatalog = packageCatalog
		results.LinuxDistribution = theDistro

		return relationships, nil
	}

	return task, nil
}

// Deprecated: will be removed in syft 1.0
func generateCatalogFileMetadataTask(app *config.Application) (Task, error) {
	if !app.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	metadataCataloger := file.NewMetadataCataloger()

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileMetadata = result
		return nil, nil
	}

	return task, nil
}

// Deprecated: will be removed in syft 1.0
func generateCatalogFileDigestsTask(app *config.Application) (Task, error) {
	if !app.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[file.DigestAlgorithmName(h)] = h
	}

	var hashes []crypto.Hash
	for _, hashStr := range app.FileMetadata.Digests {
		name := file.CleanDigestAlgorithmName(hashStr)
		hashObj, ok := supportedHashAlgorithms[name]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashes = append(hashes, hashObj)
	}

	digestsCataloger := file.NewDigestsCataloger(hashes)

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileDigests = result
		return nil, nil
	}

	return task, nil
}

// Deprecated: will be removed in syft 1.0
func generateCatalogSecretsTask(app *config.Application) (Task, error) {
	if !app.Secrets.Cataloger.Enabled {
		return nil, nil
	}

	patterns, err := file.GenerateSearchPatterns(file.DefaultSecretsPatterns, app.Secrets.AdditionalPatterns, app.Secrets.ExcludePatternNames)
	if err != nil {
		return nil, err
	}

	secretsCataloger, err := file.NewSecretsCataloger(patterns, app.Secrets.RevealValues, app.Secrets.SkipFilesAboveSize)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.Secrets.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := secretsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.Secrets = result
		return nil, nil
	}

	return task, nil
}

// Deprecated: will be removed in syft 1.0
func generateCatalogContentsTask(app *config.Application) (Task, error) {
	if !app.FileContents.Cataloger.Enabled {
		return nil, nil
	}

	contentsCataloger, err := file.NewContentsCataloger(app.FileContents.Globs, app.FileContents.SkipFilesAboveSize)
	if err != nil {
		return nil, err
	}

	task := func(results *sbom.Artifacts, src *source.Source) ([]artifact.Relationship, error) {
		resolver, err := src.FileResolver(app.FileContents.Cataloger.ScopeOpt)
		if err != nil {
			return nil, err
		}

		result, err := contentsCataloger.Catalog(resolver)
		if err != nil {
			return nil, err
		}
		results.FileContents = result
		return nil, nil
	}

	return task, nil
}

// Deprecated: will be removed in syft 1.0
func RunTask(t Task, a *sbom.Artifacts, src *source.Source, c chan<- artifact.Relationship, errs chan<- error) {
	defer close(c)

	relationships, err := t(a, src)
	if err != nil {
		errs <- err
		return
	}

	for _, relationship := range relationships {
		c <- relationship
	}
}
