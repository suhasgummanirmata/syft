package syft

import (
	"fmt"
	"sync"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

type SBOMBuilderConfig struct {
	Parallelism                 uint // TODO: not hooked up yet
	SearchScope                 source.Scope
	CaptureFileOwnershipOverlap bool
	ToolName                    string
	ToolVersion                 string
	ToolConfiguration           interface{}
	TaskGroups                  [][]Task
	packageCatalogingTasks      *[]Task
}

func DefaultSBOMBuilderConfig() *SBOMBuilderConfig {
	return &SBOMBuilderConfig{
		ToolName:    internal.ApplicationName,
		ToolVersion: version.FromBuild().Version,
		SearchScope: source.SquashedScope,
	}
}

func (c *SBOMBuilderConfig) WithParallelism(parallelism uint) *SBOMBuilderConfig {
	c.Parallelism = parallelism
	return c
}

func (c *SBOMBuilderConfig) AsTool(name, version string) *SBOMBuilderConfig {
	c.ToolName = name
	c.ToolVersion = version
	return c
}

func (c *SBOMBuilderConfig) WithToolConfiguration(config interface{}) *SBOMBuilderConfig {
	c.ToolConfiguration = config
	return c
}

func (c *SBOMBuilderConfig) WithTasks(tasks ...Task) *SBOMBuilderConfig {
	c.TaskGroups = [][]Task{tasks}
	return c
}

func (c *SBOMBuilderConfig) WithAdditionalTasks(tasks ...Task) *SBOMBuilderConfig {
	c.TaskGroups = append(c.TaskGroups, tasks)
	return c
}

func (c *SBOMBuilderConfig) WithCatalogers(src source.Metadata, cfg cataloger.Config, expression string) *SBOMBuilderConfig {
	var pkgTasks TaskDescriptors

	if expression == "" {
		switch src.Scheme {
		case source.ImageScheme:
			pkgTasks = allCatalogingTaskDescriptors(cfg).AllTags(imageTag)
		case source.FileScheme, source.DirectoryScheme:
			pkgTasks = allCatalogingTaskDescriptors(cfg).AllTags(directoryTag)
		default:
			// TODO
			panic("not implemented")
		}
	} else {
		pkgTasks = allCatalogingTaskDescriptors(cfg).Evaluate(expression)
	}

	var fileTasks []Task

	if t := generateDigestCatalogerTask(cfg.FileCatalogingSelection, cfg.FileHashers...); t != nil {
		fileTasks = append(fileTasks, t)
	}
	if t := generateMetadataCatalogerTask(cfg.FileCatalogingSelection); t != nil {
		fileTasks = append(fileTasks, t)
	}

	c.SearchScope = cfg.Search.Scope
	c.CaptureFileOwnershipOverlap = cfg.Relationships.FileOwnershipOverlap
	c.TaskGroups = append(c.TaskGroups, pkgTasks.Tasks(), fileTasks)
	c.packageCatalogingTasks = &c.TaskGroups[0]

	return c
}

func (c *SBOMBuilderConfig) WithAdditionalCatalogers(cfg cataloger.Config, catalogers ...pkg.Cataloger) *SBOMBuilderConfig {
	var tasks []Task
	for _, cat := range catalogers {
		tasks = append(tasks, newTask(cat, cfg))
	}
	if c.packageCatalogingTasks != nil {
		// add to existing package cataloging task group
		*c.packageCatalogingTasks = append(*c.packageCatalogingTasks, tasks...)
	} else {
		// prepend to ensure that package catalogers are always run first
		c.TaskGroups = append([][]Task{tasks}, c.TaskGroups...)
	}
	return c
}

func BuildSBOM(src *source.Source, cfg *SBOMBuilderConfig) (*sbom.SBOM, error) {
	resolver, err := src.FileResolver(cfg.SearchScope)
	if err != nil {
		return nil, fmt.Errorf("unable to get file resolver: %w", err)
	}

	s := sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name:          cfg.ToolName,
			Version:       cfg.ToolVersion,
			Configuration: cfg.ToolConfiguration,
		},
		Artifacts: sbom.Artifacts{
			LinuxDistribution: linux.IdentifyRelease(resolver),
		},
	}

	lock := &sync.RWMutex{}
	for _, tg := range cfg.TaskGroups {
		for _, t := range tg {
			if err := t(resolver, &s, lock); err != nil {
				return nil, err
			}
		}
	}

	// always add package to package relationships last
	if cfg.CaptureFileOwnershipOverlap {
		addFileOwnershipOverlapRelationships(&s, lock)
	}

	return nil, nil
}

func addFileOwnershipOverlapRelationships(s *sbom.SBOM, lock *sync.RWMutex) {
	lock.RLock()
	relationships := pkg.RelationshipsByFileOwnershipOverlap(s.Artifacts.PackageCatalog)
	lock.RUnlock()
	lock.Lock()
	s.Relationships = append(s.Relationships, relationships...)
	lock.Unlock()
}
