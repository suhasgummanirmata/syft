package packages

import (
	"context"
	"fmt"
	"strings"

	"github.com/wagoodman/go-partybus"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/eventloop"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Run(ctx context.Context, app *config.Application, args []string) error {
	err := validateOutputOptions(app)
	if err != nil {
		return err
	}

	writer, err := options.MakeWriter(app.Outputs, app.File, app.OutputTemplatePath)
	if err != nil {
		return err
	}

	defer func() {
		if err := writer.Close(); err != nil {
			log.Warnf("unable to write to report destination: %w", err)
		}
	}()

	// could be an image or a directory, with or without a scheme
	userInput := args[0]
	si, err := source.ParseInputWithName(userInput, app.Platform, true, app.Name)
	if err != nil {
		return fmt.Errorf("could not generate source input for packages command: %w", err)
	}

	eventBus := partybus.NewBus()
	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
	subscription := eventBus.Subscribe()

	return eventloop.EventLoop(
		execWorker(app, *si, writer),
		eventloop.SetupSignals(),
		subscription,
		stereoscope.Cleanup,
		ui.Select(options.IsVerbose(app), app.Quiet)...,
	)
}

func execWorker(app *config.Application, si source.Input, writer sbom.Writer) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		src, cleanup, err := source.New(si, app.Registry.ToOptions(), app.Exclusions)
		if cleanup != nil {
			defer cleanup()
		}
		if err != nil {
			errs <- fmt.Errorf("failed to construct source from user input %q: %w", si.UserInput, err)
			return
		}

		s, err := GenerateSBOM(src, errs, app)
		if err != nil {
			errs <- err
			return
		}

		if s == nil {
			errs <- fmt.Errorf("no SBOM produced for %q", si.UserInput)
		}

		bus.Publish(partybus.Event{
			Type:  event.Exit,
			Value: func() error { return writer.Write(*s) },
		})
	}()
	return errs
}

func GenerateSBOM(src *source.Source, errs chan error, app *config.Application) (*sbom.SBOM, error) {
	hashers, err := file.Hashers(app.FileMetadata.Digests...)
	if err != nil {
		// TODO: this is awkward, fix this
		err = fmt.Errorf("unable to create file hashers: %w", err)
		errs <- err
		return nil, err
	}

	cfg := syft.DefaultSBOMBuilderConfig().
		WithCatalogers(src.Metadata,
			cataloger.Config{
				Search: cataloger.SearchConfig{
					IncludeIndexedArchives:   app.Package.SearchIndexedArchives,
					IncludeUnindexedArchives: app.Package.SearchUnindexedArchives,
					Scope:                    source.ParseScope(app.Package.Cataloger.Scope),
				},
				Relationships: cataloger.RelationshipsConfig{
					FileOwnership:        true,  // TODO: tie to app config
					FileOwnershipOverlap: false, // TODO: tie to app config
				},
				SyntheticData: cataloger.SyntheticConfig{
					GenerateCPEs:          true, // TODO: tie to app config
					GuessLanguageFromPURL: true, // TODO: tie to app config
				},
				FileCatalogingSelection: cataloger.OwnedFilesSelection, // TODO: tie to app config
				FileHashers:             hashers,
			},
			strings.Join(app.Catalogers, ","), // TODO: update app config to just be a string?
		)

	return syft.BuildSBOM(src, cfg)
}

func validateOutputOptions(app *config.Application) error {
	var usesTemplateOutput bool
	for _, o := range app.Outputs {
		if o == template.ID.String() {
			usesTemplateOutput = true
			break
		}
	}

	if usesTemplateOutput && app.OutputTemplatePath == "" {
		return fmt.Errorf(`must specify path to template file when using "template" output format`)
	}

	return nil
}
