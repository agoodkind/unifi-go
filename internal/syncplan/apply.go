package syncplan

import (
	"context"
	"fmt"
	"log/slog"

	"goodkind.io/unifi-go/internal/unifiapi"
)

// Apply sends one collection's plan to the controller. It stops at the first
// rejected record so the operator sees which change failed and what preceded it.
func Apply(ctx context.Context, client *unifiapi.Client, collection unifiapi.Collection, plan Plan) error {
	slog.Info("apply plan", slog.String("collection", string(collection.Name)), slog.Int("changes", len(plan.Changes)))
	for _, change := range plan.Changes {
		if err := applyChange(ctx, client, collection, change); err != nil {
			return err
		}
	}
	return nil
}

func applyChange(ctx context.Context, client *unifiapi.Client, collection unifiapi.Collection, change Change) error {
	switch change.Action {
	case ActionCreate:
		if _, err := client.Create(ctx, collection, change.Record); err != nil {
			return recordFailure(collection, change, err)
		}
	case ActionUpdate:
		if _, err := client.Update(ctx, collection, change.Identity, change.ID, change.Record); err != nil {
			return recordFailure(collection, change, err)
		}
	case ActionDelete:
		if err := client.Delete(ctx, collection, change.Identity, change.ID); err != nil {
			return recordFailure(collection, change, err)
		}
	default:
		return fmt.Errorf("collection %s has an unknown action %q", collection.Name, change.Action)
	}
	return nil
}

func recordFailure(collection unifiapi.Collection, change Change, err error) error {
	slog.Error("record change failed",
		slog.String("collection", string(collection.Name)),
		slog.String("identity", change.Identity),
		slog.String("action", string(change.Action)),
		slog.String("error", err.Error()))
	return fmt.Errorf("%s %s %q: %w", change.Action, collection.Name, change.Identity, err)
}
