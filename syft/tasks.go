package syft

import (
	"crypto"
	"fmt"
	"strings"
	"sync"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/pkg/cataloger/alpm"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/dart"
	"github.com/anchore/syft/syft/pkg/cataloger/deb"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/haskell"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/portage"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/rpm"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	sbomCataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	installedTag = "installed"
	declaredTag  = "declared"
	imageTag     = "image"
	directoryTag = "dir"
	packageTag   = "package"
	osTag        = "os"
	languageTag  = "language"
)

type Task func(source.FileResolver, *sbom.SBOM, *sync.RWMutex) error

type TaskDescriptor struct {
	Name string
	Tags *strset.Set
	Task Task
}

type TaskDescriptors []TaskDescriptor

func (tds TaskDescriptors) AllTags(tags ...string) TaskDescriptors {
	var result []TaskDescriptor
	for _, td := range tds {
		if td.Tags.Has(tags...) {
			result = append(result, td)
		}
	}
	return result
}

func (tds TaskDescriptors) AnyTags(tags ...string) TaskDescriptors {
	var result []TaskDescriptor
	for _, td := range tds {
		if td.Tags.HasAny(tags...) {
			result = append(result, td)
		}
	}
	return result
}

func (tds TaskDescriptors) Tasks() []Task {
	var result []Task
	for _, td := range tds {
		result = append(result, td.Task)
	}
	return result
}

// Evaluate the tag expression.
// example: "installed+python, os, sbom-cataloger"
// ... means:
// - all catalogers that have both the "installed" and "python" tags...
// - and additionally all catalogers that have the "os" tag...
// - and add the "sbom-cataloger" by name.
func (tds TaskDescriptors) Evaluate(expression string) TaskDescriptors {
	var result []TaskDescriptor
	expression = strings.ReplaceAll(strings.ToLower(expression), " ", "")
	fields := strings.Split(expression, ",")
	for _, field := range fields {
		requiredTags := strings.Split(field, "+")
		result = append(result, tds.AllTags(requiredTags...)...)
	}
	return result
}

func allCatalogingTaskDescriptors(cfg cataloger.Config) TaskDescriptors {
	return []TaskDescriptor{
		// OS package installed catalogers
		newTaskDescriptor(cfg, alpm.NewAlpmdbCataloger(), directoryTag, installedTag, imageTag, packageTag, osTag, "alpm", "archlinux"),
		newTaskDescriptor(cfg, apkdb.NewApkdbCataloger(), directoryTag, installedTag, imageTag, packageTag, osTag, "apk", "alpine"),
		newTaskDescriptor(cfg, deb.NewDpkgdbCataloger(), directoryTag, installedTag, imageTag, packageTag, osTag, "dpkg", "debian"),
		newTaskDescriptor(cfg, portage.NewPortageCataloger(), directoryTag, installedTag, imageTag, packageTag, osTag, "portage", "gentoo"),
		newTaskDescriptor(cfg, rpm.NewRpmDBCataloger(), directoryTag, installedTag, imageTag, packageTag, osTag, "rpm", "redhat"),

		// OS package declared catalogers
		newTaskDescriptor(cfg, rpm.NewFileCataloger(), declaredTag, directoryTag, packageTag, osTag, "rpm", "redhat"),

		// language-specific package installed catalogers
		newTaskDescriptor(cfg, dotnet.NewDotnetDepsCataloger(), installedTag, imageTag, packageTag, languageTag, "dotnet", "c#"),
		newTaskDescriptor(cfg, javascript.NewJavascriptPackageCataloger(), installedTag, imageTag, packageTag, languageTag, "javascript", "node"),
		newTaskDescriptor(cfg, javascript.NewNodeBinaryCataloger(), installedTag, imageTag, packageTag, languageTag, "javascript", "node"),
		newTaskDescriptor(cfg, php.NewPHPComposerInstalledCataloger(), installedTag, imageTag, packageTag, languageTag, "php", "composer"),
		newTaskDescriptor(cfg, ruby.NewGemSpecCataloger(), installedTag, imageTag, packageTag, languageTag, "ruby", "gem"),
		newTaskDescriptor(cfg, rust.NewCargoLockCataloger(), installedTag, imageTag, packageTag, languageTag, "rust", "binary"),

		// language-specific package declared catalogers
		newTaskDescriptor(cfg, cpp.NewConanCataloger(), declaredTag, directoryTag, packageTag, languageTag, "cpp", "conan"),
		newTaskDescriptor(cfg, dart.NewPubspecLockCataloger(), declaredTag, directoryTag, packageTag, languageTag, "dart"),
		newTaskDescriptor(cfg, dotnet.NewDotnetDepsCataloger(), declaredTag, directoryTag, packageTag, languageTag, "dotnet", "c#"),
		newTaskDescriptor(cfg, haskell.NewHackageCataloger(), declaredTag, directoryTag, packageTag, languageTag, "haskell", "cabal"),
		newTaskDescriptor(cfg, golang.NewGoModFileCataloger(), declaredTag, directoryTag, packageTag, languageTag, "go", "golang", "gomod"),
		newTaskDescriptor(cfg, java.NewJavaPomCataloger(), declaredTag, directoryTag, packageTag, languageTag, "java", "maven"),
		newTaskDescriptor(cfg, javascript.NewJavascriptLockCataloger(), declaredTag, directoryTag, packageTag, languageTag, "javascript", "node"),
		newTaskDescriptor(cfg, javascript.NewNodeBinaryCataloger(), declaredTag, directoryTag, packageTag, languageTag, "javascript", "node", "binary"),
		newTaskDescriptor(cfg, php.NewPHPComposerLockCataloger(), declaredTag, directoryTag, packageTag, languageTag, "php", "composer"),
		newTaskDescriptor(cfg, python.NewPythonIndexCataloger(), declaredTag, directoryTag, packageTag, languageTag, "python"),
		newTaskDescriptor(cfg, ruby.NewGemFileLockCataloger(), declaredTag, directoryTag, packageTag, languageTag, "ruby", "gem"),
		newTaskDescriptor(cfg, rust.NewCargoLockCataloger(), declaredTag, directoryTag, packageTag, languageTag, "rust", "cargo"),
		newTaskDescriptor(cfg, swift.NewCocoapodsCataloger(), declaredTag, directoryTag, packageTag, languageTag, "swift", "cocoapods"),

		// language-specific package declared & installed catalogers
		newTaskDescriptor(cfg, python.NewPythonPackageCataloger(), directoryTag, installedTag, imageTag, packageTag, languageTag, "python"),
		newTaskDescriptor(cfg, golang.NewGoModuleBinaryCataloger(), directoryTag, installedTag, imageTag, packageTag, languageTag, "go", "golang", "gomod", "binary"),
		newTaskDescriptor(cfg, java.NewJavaCataloger(cfg.Java()), directoryTag, installedTag, imageTag, packageTag, languageTag, "java", "maven"),

		// other package catalogers
		newTaskDescriptor(cfg, sbomCataloger.NewSBOMCataloger(), declaredTag, directoryTag, imageTag, packageTag, "sbom"),
	}
}

func newTaskDescriptor(cfg cataloger.Config, c pkg.Cataloger, tags ...string) TaskDescriptor {
	return TaskDescriptor{
		Name: c.Name(),
		Tags: strset.New(tags...),
		Task: newTask(c, cfg),
	}
}

func newTask(cataloger pkg.Cataloger, cfg cataloger.Config) Task {
	return func(resolver source.FileResolver, sbom *sbom.SBOM, lock *sync.RWMutex) error {
		pkgs, relationships, err := cataloger.Catalog(resolver)
		if err != nil {
			return fmt.Errorf("unable to catalog packages with %q: %w", cataloger.Name(), err)
		}

		for i, p := range pkgs {
			if cfg.SyntheticData.GenerateCPEs {
				// generate CPEs (note: this is excluded from package ID, so is safe to mutate)
				// we might have binary classified CPE already with the package so we want to append here
				p.CPEs = append(p.CPEs, cpe.Generate(p)...)
			}

			if cfg.SyntheticData.GuessLanguageFromPURL {
				// if we were not able to identify the language we have an opportunity
				// to try and get this value from the PURL. Worst case we assert that
				// we could not identify the language at either stage and set UnknownLanguage
				if p.Language == "" {
					p.Language = pkg.LanguageFromPURL(p.PURL)
				}
			}

			if cfg.Relationships.FileOwnership {
				// create file-to-package relationships for files owned by the package
				owningRelationships, err := packageFileOwnershipRelationships(p, resolver)
				if err != nil {
					log.Warnf("unable to create any package-file relationships for package name=%q type=%q: %w", p.Name, p.Type, err)
				} else {
					relationships = append(relationships, owningRelationships...)
				}
			}

			pkgs[i] = p
		}
		lock.Lock()
		sbom.Artifacts.PackageCatalog.Add(pkgs...)
		sbom.Relationships = append(sbom.Relationships, relationships...)
		lock.Unlock()

		return nil
	}
}

func packageFileOwnershipRelationships(p pkg.Package, resolver source.FilePathResolver) ([]artifact.Relationship, error) {
	fileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return nil, nil
	}

	locations := map[artifact.ID]source.Location{}

	for _, path := range fileOwner.OwnedFiles() {
		pathRefs, err := resolver.FilesByPath(path)
		if err != nil {
			return nil, fmt.Errorf("unable to find path for path=%q: %w", path, err)
		}

		if len(pathRefs) == 0 {
			// ideally we want to warn users about missing files from a package, however, it is very common for
			// container image authors to delete files that are not needed in order to keep image sizes small. Adding
			// a warning here would be needlessly noisy (even for popular base images).
			continue
		}

		for _, ref := range pathRefs {
			if oldRef, ok := locations[ref.Coordinates.ID()]; ok {
				log.Debugf("found path duplicate of %s", oldRef.RealPath)
			}
			locations[ref.Coordinates.ID()] = ref
		}
	}

	var relationships []artifact.Relationship
	for _, location := range locations {
		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   location.Coordinates,
			Type: artifact.ContainsRelationship,
		})
	}
	return relationships, nil
}

func generateDigestCatalogerTask(selection cataloger.FileCatalogingSelection, hashers ...crypto.Hash) Task {
	if selection == cataloger.NoFilesSelection || len(hashers) == 0 {
		return nil
	}

	digestsCataloger := file.NewDigestsCataloger(hashers)

	return func(resolver source.FileResolver, sbom *sbom.SBOM, lock *sync.RWMutex) error {
		var coordinates []source.Coordinates
		if selection == cataloger.OwnedFilesSelection {
			lock.RLock()

			for _, r := range sbom.Relationships {
				// TODO: double check this logic
				if r.Type != artifact.ContainsRelationship {
					continue
				}
				if _, ok := r.From.(pkg.Package); !ok {
					continue
				}
				if c, ok := r.To.(source.Coordinates); ok {
					coordinates = append(coordinates, c)
				}
			}
			lock.RUnlock()
		}

		result, err := digestsCataloger.Catalog(resolver, coordinates...)
		if err != nil {
			return err
		}

		lock.Lock()
		sbom.Artifacts.FileDigests = result
		lock.Unlock()

		return nil
	}
}

func generateMetadataCatalogerTask(selection cataloger.FileCatalogingSelection) Task {
	if selection == cataloger.NoFilesSelection {
		return nil
	}

	metadataCataloger := file.NewMetadataCataloger()

	return func(resolver source.FileResolver, sbom *sbom.SBOM, lock *sync.RWMutex) error {
		var coordinates []source.Coordinates
		if selection == cataloger.OwnedFilesSelection {
			lock.RLock()

			for _, r := range sbom.Relationships {
				if r.Type != artifact.ContainsRelationship {
					continue
				}
				if _, ok := r.From.(pkg.Package); !ok {
					continue
				}
				if c, ok := r.To.(source.Coordinates); ok {
					coordinates = append(coordinates, c)
				}
			}
			lock.RUnlock()
		}

		result, err := metadataCataloger.Catalog(resolver, coordinates...)
		if err != nil {
			return err
		}

		lock.Lock()
		sbom.Artifacts.FileMetadata = result
		lock.Unlock()

		return nil
	}
}
