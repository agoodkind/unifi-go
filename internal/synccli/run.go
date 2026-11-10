// Package synccli runs commands that synchronize controller records with a
// local store.
package synccli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"goodkind.io/unifi-go/internal/syncplan"
	"goodkind.io/unifi-go/internal/syncstore"
	"goodkind.io/unifi-go/internal/unifiapi"
)

type syncDirection string

const (
	// syncPull copies controller records into the local store.
	syncPull syncDirection = "pull"
	// syncPush copies stored records into the controller.
	syncPush syncDirection = "push"
)

var (
	errDirection           = errors.New("sync requires pull or push")
	errInvalidArguments    = errors.New("invalid command arguments")
	errUnexpectedArguments = errors.New("unexpected command arguments")
	errControllerRequired  = errors.New("controller-url is required")
	errUnknownCollection   = errors.New("unknown collection")
	errEmptyCollections    = errors.New("collections selected no collection")
	errRequiredInput       = errors.New("is required")
	errReadInput           = errors.New("cannot read")
	errSingleLineInput     = errors.New("must contain one line")
)

type syncOptions struct {
	direction   syncDirection
	controller  unifiapi.Config
	directory   string
	collections []unifiapi.Collection
	dryRun      bool
	prune       bool
}

// Run synchronizes controller records with the local store.
//
// The first argument selects pull or push. A dry run prints proposed changes
// without updating destination records.
//
// For example:
//
//	err := Run(ctx, args, output)
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errDirection
	}

	direction := syncDirection(args[0])
	if direction != syncPull && direction != syncPush {
		return errDirection
	}

	options, err := parseSyncFlags(direction, args[1:])
	if err != nil {
		return err
	}

	client, err := unifiapi.Dial(ctx, options.controller)
	if err != nil {
		return Failure("open controller session", err)
	}
	defer client.Close()
	store, err := syncstore.Open(options.directory)
	if err != nil {
		return Failure("open record store", err)
	}

	return syncCollections(ctx, client, store, options, output)
}

func parseSyncFlags(direction syncDirection, args []string) (syncOptions, error) {
	empty := syncOptions{
		direction: "",
		controller: unifiapi.Config{
			BaseURL:  "",
			Site:     "",
			Username: "",
			Password: "",
			Insecure: false,
		},
		directory:   "",
		collections: nil,
		dryRun:      false,
		prune:       false,
	}
	flags := flag.NewFlagSet("sync "+string(direction), flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	controllerURL := flags.String("controller-url", "", "UniFi Network Application base URL")
	site := flags.String("site", "default", "controller site name")
	usernameFile := flags.String("username-file", "", "controller username file")
	passwordFile := flags.String("password-file", "", "controller password file")
	directory := flags.String("dir", "state/controller", "stored record directory")
	selected := flags.String(
		"collections",
		"",
		"comma separated collections, empty selects every collection",
	)
	insecure := flags.Bool("insecure", false, "accept the controller's own certificate")
	dryRun := flags.Bool("dry-run", false, "show the difference and change nothing")
	prune := flags.Bool("prune", false, "remove destination records the source no longer holds")
	if err := flags.Parse(args); err != nil {
		return empty, errInvalidArguments
	}

	if flags.NArg() != 0 {
		return empty, errUnexpectedArguments
	}

	if *controllerURL == "" {
		return empty, errControllerRequired
	}

	username, err := readSyncSecret(*usernameFile, "username-file")
	if err != nil {
		return empty, err
	}

	password, err := readSyncSecret(*passwordFile, "password-file")
	if err != nil {
		return empty, err
	}

	collections, err := selectCollections(*selected)
	if err != nil {
		return empty, err
	}

	secret := password

	return syncOptions{
		direction: direction,
		controller: unifiapi.Config{
			BaseURL:  *controllerURL,
			Site:     *site,
			Username: username,
			Password: secret,
			Insecure: *insecure,
		},
		directory:   *directory,
		collections: collections,
		dryRun:      *dryRun,
		prune:       *prune,
	}, nil
}

func selectCollections(selected string) ([]unifiapi.Collection, error) {
	if strings.TrimSpace(selected) == "" {
		return unifiapi.Collections(), nil
	}

	var result []unifiapi.Collection

	for name := range strings.SplitSeq(selected, ",") {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}

		collection, found := unifiapi.Lookup(unifiapi.CollectionName(trimmed))
		if !found {
			slog.Error("controller collection selection failed", "err", errUnknownCollection)

			return nil, fmt.Errorf("%w %q", errUnknownCollection, trimmed)
		}

		result = append(result, collection)
	}

	if len(result) == 0 {
		return nil, errEmptyCollections
	}

	return result, nil
}

func readSyncSecret(path, name string) (string, error) {
	if path == "" {
		slog.Error("controller credential file path missing", "flag", name, "err", errRequiredInput)

		return "", fmt.Errorf("%s %w", name, errRequiredInput)
	}

	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		slog.Error("controller credential file read failed", "flag", name, "err", err)

		return "", fmt.Errorf("%w %s", errReadInput, name)
	}

	value := strings.TrimRight(string(data), "\r\n")
	if value == "" || strings.ContainsAny(value, "\r\n") {
		slog.Error(
			"controller credential file requires one line",
			"flag",
			name,
			"err",
			errSingleLineInput,
		)

		return "", fmt.Errorf("%s %w", name, errSingleLineInput)
	}

	return value, nil
}

// collectionSides stores source and destination records for one collection.
type collectionSides struct {
	collection  unifiapi.Collection
	source      []unifiapi.Record
	destination []unifiapi.Record
	plan        syncplan.Plan
}

func syncCollections(
	ctx context.Context,
	client *unifiapi.Client,
	store *syncstore.Store,
	options syncOptions,
	output io.Writer,
) error {
	sides, planned, err := planSync(ctx, client, store, options)
	if err != nil {
		return err
	}

	fmt.Fprintf(
		output,
		"%s %s: %s\n\n",
		options.direction,
		destinationName(options.direction),
		syncplan.Summary(planned),
	)
	if err := syncplan.Render(output, planned); err != nil {
		return Failure("write planned changes", err)
	}

	if planned.Empty() || options.dryRun {
		return nil
	}

	if err := applySync(ctx, client, store, options, sides); err != nil {
		return err
	}

	return reportApplied(ctx, client, store, options, sides, output)
}

func planSync(
	ctx context.Context,
	client *unifiapi.Client,
	store *syncstore.Store,
	options syncOptions,
) ([]collectionSides, syncplan.Plan, error) {
	sides := make([]collectionSides, 0, len(options.collections))
	combined := syncplan.Plan{Changes: nil}

	for _, collection := range options.collections {
		source, destination, err := readSides(ctx, client, store, options, collection)
		if err != nil {
			return nil, syncplan.Plan{Changes: nil}, err
		}

		plan, err := syncplan.Compare(collection, source, destination, options.prune)
		if err != nil {
			return nil, syncplan.Plan{
				Changes: nil,
			}, Failure("compare "+string(collection.Name), err)
		}

		sides = append(
			sides,
			collectionSides{
				collection:  collection,
				source:      source,
				destination: destination,
				plan:        plan,
			},
		)
		combined.Changes = append(combined.Changes, plan.Changes...)
	}

	return sides, combined, nil
}

func readSides(
	ctx context.Context,
	client *unifiapi.Client,
	store *syncstore.Store,
	options syncOptions,
	collection unifiapi.Collection,
) ([]unifiapi.Record, []unifiapi.Record, error) {
	remote, err := client.List(ctx, collection)
	if err != nil {
		return nil, nil, Failure("read controller "+string(collection.Name), err)
	}

	local, err := store.Read(client.Site(), collection)
	if err != nil {
		return nil, nil, Failure("read stored "+string(collection.Name), err)
	}

	if options.direction == syncPull {
		return remote, local, nil
	}

	return local, remote, nil
}

func applySync(
	ctx context.Context,
	client *unifiapi.Client,
	store *syncstore.Store,
	options syncOptions,
	sides []collectionSides,
) error {
	for _, side := range sides {
		if side.plan.Empty() {
			continue
		}

		if options.direction == syncPush {
			if err := syncplan.Apply(ctx, client, side.collection, side.plan); err != nil {
				return Failure("apply "+string(side.collection.Name), err)
			}

			continue
		}

		stored := make([]unifiapi.Record, 0, len(side.source))
		for _, record := range side.source {
			stored = append(stored, side.collection.Project(record))
		}

		if err := store.Write(client.Site(), side.collection, stored); err != nil {
			return Failure("store "+string(side.collection.Name), err)
		}
	}

	return nil
}

// reportApplied reads the destination after applying changes.
// It renders the applied changes and any remaining differences.
func reportApplied(
	ctx context.Context,
	client *unifiapi.Client,
	store *syncstore.Store,
	options syncOptions,
	sides []collectionSides,
	output io.Writer,
) error {
	applied := syncplan.Plan{Changes: nil}
	remaining := syncplan.Plan{Changes: nil}

	for _, side := range sides {
		after, err := readDestination(ctx, client, store, options, side.collection)
		if err != nil {
			return err
		}

		change, err := syncplan.Compare(side.collection, after, side.destination, true)
		if err != nil {
			return Failure("compare applied "+string(side.collection.Name), err)
		}

		applied.Changes = append(applied.Changes, change.Changes...)
		left, err := syncplan.Compare(side.collection, side.source, after, options.prune)
		if err != nil {
			return Failure("compare remaining "+string(side.collection.Name), err)
		}

		remaining.Changes = append(remaining.Changes, left.Changes...)
	}

	fmt.Fprintf(
		output,
		"\napplied to %s: %s\n\n",
		destinationName(options.direction),
		syncplan.Summary(applied),
	)
	if err := syncplan.Render(output, applied); err != nil {
		return Failure("write applied changes", err)
	}

	if remaining.Empty() {
		return nil
	}

	fmt.Fprintf(output, "\nstill differing: %s\n\n", syncplan.Summary(remaining))
	if err := syncplan.Render(output, remaining); err != nil {
		return Failure("write remaining differences", err)
	}

	return nil
}

func readDestination(
	ctx context.Context,
	client *unifiapi.Client,
	store *syncstore.Store,
	options syncOptions,
	collection unifiapi.Collection,
) ([]unifiapi.Record, error) {
	if options.direction == syncPush {
		records, err := client.List(ctx, collection)
		if err != nil {
			return nil, Failure("re-read controller "+string(collection.Name), err)
		}

		return records, nil
	}

	records, err := store.Read(client.Site(), collection)
	if err != nil {
		return nil, Failure("re-read stored "+string(collection.Name), err)
	}

	return records, nil
}

func destinationName(direction syncDirection) string {
	if direction == syncPull {
		return "the stored records"
	}

	return "the controller"
}

// Failure logs an operation error and adds the operation to its message.
//
// The returned error wraps the original error for callers that inspect it.
//
// For example:
//
//	err = Failure("read controller records", err)
func Failure(message string, err error) error {
	slog.Error(message, slog.String("error", err.Error()))

	return fmt.Errorf("%s: %w", message, err)
}
