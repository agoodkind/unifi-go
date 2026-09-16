package syncplan

import (
	"fmt"
	"io"
	"strings"

	"goodkind.io/unifi-go/internal/unifiapi"
)

const (
	valueWidth   = 96
	fieldIndent  = "      "
	recordIndent = "  "
)

// Render writes the plan as reviewable text, grouped by collection.
func Render(output io.Writer, plan Plan) error {
	if plan.Empty() {
		if _, err := io.WriteString(output, "no differences\n"); err != nil {
			return failure("write plan", err)
		}
		return nil
	}
	current := unifiapi.CollectionName("")
	for _, change := range plan.Changes {
		if change.Collection != current {
			current = change.Collection
			if _, err := fmt.Fprintf(output, "%s\n", current); err != nil {
				return failure("write plan collection", err)
			}
		}
		if err := renderChange(output, change); err != nil {
			return err
		}
	}
	return nil
}

func renderChange(output io.Writer, change Change) error {
	if _, err := fmt.Fprintf(output, "%s%s %q\n", recordIndent, change.Action, change.Identity); err != nil {
		return failure("write plan record", err)
	}
	for _, field := range change.Fields {
		line := fmt.Sprintf("%s%s: %s -> %s\n", fieldIndent, field.Field, absent(truncate(field.Before)), absent(truncate(field.After)))
		if _, err := io.WriteString(output, line); err != nil {
			return failure("write plan field", err)
		}
	}
	return nil
}

// Summary returns one line naming how much work the plan holds.
func Summary(plan Plan) string {
	created, updated, deleted := plan.Counts()
	return fmt.Sprintf("%d to create, %d to update, %d to remove", created, updated, deleted)
}

func truncate(value string) string {
	if len(value) <= valueWidth {
		return value
	}
	return value[:valueWidth] + "..."
}

func absent(value string) string {
	if strings.TrimSpace(value) == "" {
		return "(absent)"
	}
	return value
}
