// Package syncplan compares controller records between two sides and describes
// the change each side needs, without applying anything.
package syncplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"goodkind.io/unifi-go/internal/syncstore"
	"goodkind.io/unifi-go/internal/unifiapi"
)

// Action names what one record needs.
type Action string

const (
	// ActionCreate adds a record the destination lacks.
	ActionCreate Action = "create"
	// ActionUpdate changes fields on a record both sides hold.
	ActionUpdate Action = "update"
	// ActionDelete removes a record the source no longer holds.
	ActionDelete Action = "delete"
)

// FieldChange records one differing field on one record.
type FieldChange struct {
	Field  string
	Before string
	After  string
}

// Change describes the work one record needs on the destination.
type Change struct {
	Collection unifiapi.CollectionName
	Identity   string
	Action     Action
	Fields     []FieldChange
	Record     unifiapi.Record
	ID         string
}

// Plan is the ordered work one comparison produced.
type Plan struct{ Changes []Change }

// Empty reports whether the destination already matches the source.
func (plan Plan) Empty() bool { return len(plan.Changes) == 0 }

// Counts returns how many records the plan creates, updates, and deletes.
func (plan Plan) Counts() (int, int, int) {
	created, updated, deleted := 0, 0, 0
	for _, change := range plan.Changes {
		switch change.Action {
		case ActionCreate:
			created++
		case ActionUpdate:
			updated++
		case ActionDelete:
			deleted++
		}
	}
	return created, updated, deleted
}

// Compare returns the change the destination needs to match the source. Records
// the source no longer holds produce a delete only when prune is set, because a
// partial source would otherwise remove live configuration.
func Compare(collection unifiapi.Collection, source, destination []unifiapi.Record, prune bool) (Plan, error) {
	sourceByIdentity, sourceOrder, err := index(collection, source)
	if err != nil {
		return Plan{Changes: nil}, err
	}
	destinationByIdentity, destinationOrder, err := index(collection, destination)
	if err != nil {
		return Plan{Changes: nil}, err
	}
	var changes []Change
	for _, identity := range sourceOrder {
		existing, present := destinationByIdentity[identity]
		if !present {
			change, err := createChange(collection, identity, sourceByIdentity[identity])
			if err != nil {
				return Plan{Changes: nil}, err
			}
			changes = append(changes, change)
			continue
		}
		change, changed, err := updateChange(collection, identity, sourceByIdentity[identity], existing)
		if err != nil {
			return Plan{Changes: nil}, err
		}
		if changed {
			changes = append(changes, change)
		}
	}
	if !prune {
		return Plan{Changes: changes}, nil
	}
	for _, identity := range destinationOrder {
		if _, present := sourceByIdentity[identity]; present {
			continue
		}
		id, _ := destinationByIdentity[identity].Text("_id")
		changes = append(changes, Change{
			Collection: collection.Name, Identity: identity, Action: ActionDelete,
			Fields: nil, Record: nil, ID: id,
		})
	}
	return Plan{Changes: changes}, nil
}

func index(collection unifiapi.Collection, records []unifiapi.Record) (map[string]unifiapi.Record, []string, error) {
	byIdentity := make(map[string]unifiapi.Record, len(records))
	order := make([]string, 0, len(records))
	for _, record := range records {
		identity, present := record.Text(string(collection.Identity))
		if !present || identity == "" {
			return nil, nil, fmt.Errorf("collection %s holds a record without a %s", collection.Name, collection.Identity)
		}
		if _, duplicate := byIdentity[identity]; duplicate {
			return nil, nil, fmt.Errorf("collection %s holds two records named %q", collection.Name, identity)
		}
		byIdentity[identity] = record
		order = append(order, identity)
	}
	slices.Sort(order)
	return byIdentity, order, nil
}

func createChange(collection unifiapi.Collection, identity string, source unifiapi.Record) (Change, error) {
	record := unifiapi.Record{}
	var fields []FieldChange
	for field, raw := range source {
		if !collection.Comparable(field) {
			continue
		}
		record[field] = raw
		text, err := display(field, raw)
		if err != nil {
			return Change{Collection: "", Identity: "", Action: "", Fields: nil, Record: nil, ID: ""}, err
		}
		fields = append(fields, FieldChange{Field: field, Before: "", After: text})
	}
	record[string(collection.Identity)] = source[string(collection.Identity)]
	slices.SortFunc(fields, func(left, right FieldChange) int { return strings.Compare(left.Field, right.Field) })
	return Change{
		Collection: collection.Name, Identity: identity, Action: ActionCreate,
		Fields: fields, Record: record, ID: "",
	}, nil
}

func updateChange(collection unifiapi.Collection, identity string, source, destination unifiapi.Record) (Change, bool, error) {
	record := destination.Clone()
	var fields []FieldChange
	for field, raw := range source {
		if !collection.Comparable(field) {
			continue
		}
		same, err := sameValue(destination[field], raw)
		if err != nil {
			return Change{Collection: "", Identity: "", Action: "", Fields: nil, Record: nil, ID: ""}, false, err
		}
		if same {
			continue
		}
		before, err := display(field, destination[field])
		if err != nil {
			return Change{Collection: "", Identity: "", Action: "", Fields: nil, Record: nil, ID: ""}, false, err
		}
		after, err := display(field, raw)
		if err != nil {
			return Change{Collection: "", Identity: "", Action: "", Fields: nil, Record: nil, ID: ""}, false, err
		}
		record[field] = raw
		fields = append(fields, FieldChange{Field: field, Before: before, After: after})
	}
	if len(fields) == 0 {
		return Change{Collection: "", Identity: "", Action: "", Fields: nil, Record: nil, ID: ""}, false, nil
	}
	slices.SortFunc(fields, func(left, right FieldChange) int { return strings.Compare(left.Field, right.Field) })
	id, _ := destination.Text("_id")
	return Change{
		Collection: collection.Name, Identity: identity, Action: ActionUpdate,
		Fields: fields, Record: record, ID: id,
	}, true, nil
}

func sameValue(left, right json.RawMessage) (bool, error) {
	if left == nil && right == nil {
		return true, nil
	}
	if left == nil || right == nil {
		return false, nil
	}
	leftText, err := syncstore.MarshalCanonical(left)
	if err != nil {
		return false, failure("canonicalize stored value", err)
	}
	rightText, err := syncstore.MarshalCanonical(right)
	if err != nil {
		return false, failure("canonicalize source value", err)
	}
	return bytes.Equal(leftText, rightText), nil
}

func failure(message string, err error) error {
	slog.Error(message, slog.String("error", err.Error()))
	return fmt.Errorf("%s: %w", message, err)
}

// display returns the reviewable text of one field value. Every credential
// member, at any depth, shows a digest so a change stays visible without
// printing the secret.
func display(field string, raw json.RawMessage) (string, error) {
	if raw == nil {
		return "", nil
	}
	safe, err := redact(field, raw)
	if err != nil {
		return "", err
	}
	compact := new(bytes.Buffer)
	if err := json.Compact(compact, safe); err != nil {
		return "", failure("compact "+field+" value", err)
	}
	return compact.String(), nil
}
