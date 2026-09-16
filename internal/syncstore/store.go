// Package syncstore keeps controller records as a reviewable directory of JSON
// files, one file for each record.
package syncstore

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"goodkind.io/unifi-go/internal/unifiapi"
)

const (
	directoryMode = 0o700
	fileMode      = 0o600
	fileSuffix    = ".json"
	maxRecordSize = 8 << 20
)

// Store reads and writes controller records under one directory.
type Store struct{ root string }

// Open prepares the directory that holds the stored records.
func Open(root string) (*Store, error) {
	slog.Info("record store open", slog.String("root", root))
	if root == "" {
		return nil, fmt.Errorf("record store needs a directory")
	}
	cleaned := filepath.Clean(root)
	if err := os.MkdirAll(cleaned, directoryMode); err != nil {
		return nil, failure("create record store directory", err)
	}
	return &Store{root: cleaned}, nil
}

func (store *Store) directory(site string, collection unifiapi.Collection) string {
	return filepath.Join(store.root, encodeName(site), encodeName(string(collection.Name)))
}

// Read returns every stored record in one collection, ordered by identity. A
// collection with no directory reads as empty, which is what a first pull sees.
func (store *Store) Read(site string, collection unifiapi.Collection) ([]unifiapi.Record, error) {
	directory := store.directory(site, collection)
	slog.Info("record store read", slog.String("collection", string(collection.Name)), slog.String("directory", directory))
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, failure("read record directory", err)
	}
	records := make([]unifiapi.Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		record, err := readRecord(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	slices.SortFunc(records, func(left, right unifiapi.Record) int {
		leftName, _ := left.Text(string(collection.Identity))
		rightName, _ := right.Text(string(collection.Identity))
		return strings.Compare(leftName, rightName)
	})
	return records, nil
}

// Write replaces the stored collection with these records and removes the files
// of records the source no longer holds.
func (store *Store) Write(site string, collection unifiapi.Collection, records []unifiapi.Record) error {
	directory := store.directory(site, collection)
	slog.Info("record store write", slog.String("collection", string(collection.Name)), slog.Int("records", len(records)))
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return failure("create collection directory", err)
	}
	keep := make(map[string]struct{}, len(records))
	for _, record := range records {
		identity, present := record.Text(string(collection.Identity))
		if !present || identity == "" {
			return fmt.Errorf("collection %s holds a record without a %s", collection.Name, collection.Identity)
		}
		name := encodeName(identity) + fileSuffix
		keep[name] = struct{}{}
		if err := writeRecord(filepath.Join(directory, name), record); err != nil {
			return err
		}
	}
	return store.removeStale(directory, keep)
}

func (store *Store) removeStale(directory string, keep map[string]struct{}) error {
	slog.Info("record store prune", slog.String("directory", directory), slog.Int("kept", len(keep)))
	entries, err := os.ReadDir(directory)
	if err != nil {
		return failure("read collection directory", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), fileSuffix) {
			continue
		}
		if _, wanted := keep[entry.Name()]; wanted {
			continue
		}
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
			return failure("remove stale record file", err)
		}
	}
	return nil
}

func readRecord(path string) (unifiapi.Record, error) {
	slog.Debug("record file read", slog.String("path", path))
	// #nosec G304 -- path is built from the operator-supplied store directory
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, failure("read record file", err)
	}
	if len(data) > maxRecordSize {
		return nil, fmt.Errorf("record file %s exceeds 8 MiB", filepath.Base(path))
	}
	var record unifiapi.Record
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, failure("decode record file "+filepath.Base(path), err)
	}
	return record, nil
}

func writeRecord(path string, record unifiapi.Record) error {
	slog.Debug("record file write", slog.String("path", path))
	encoded, err := json.Marshal(record)
	if err != nil {
		return failure("encode record", err)
	}
	text, err := MarshalCanonical(encoded)
	if err != nil {
		return failure("canonicalize record", err)
	}
	if err := os.WriteFile(path, text, fileMode); err != nil {
		return failure("write record file", err)
	}
	return nil
}

// encodeName maps one identity onto a portable file name. Every byte outside
// the unreserved set becomes a percent escape, so two identities never share a
// file and the mapping stays reversible by eye.
func encodeName(identity string) string {
	var builder strings.Builder
	for index := range len(identity) {
		character := identity[index]
		switch {
		case character >= 'A' && character <= 'Z',
			character >= 'a' && character <= 'z',
			character >= '0' && character <= '9',
			character == '.' || character == '_' || character == '-':
			builder.WriteByte(character)
		default:
			fmt.Fprintf(&builder, "%%%02X", character)
		}
	}
	if builder.Len() == 0 {
		return "%00"
	}
	return builder.String()
}

func failure(message string, err error) error {
	slog.Error(message, slog.String("error", err.Error()))
	return fmt.Errorf("%s: %w", message, err)
}
