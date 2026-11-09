package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"goodkind.io/unifi-go/internal/syncstore"
	"goodkind.io/unifi-go/internal/unifiapi"
)

type syncTestRecord struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
	VLAN int    `json:"vlan"`
}

type syncTestEnvelope struct {
	Meta struct {
		Result  string `json:"rc"`
		Message string `json:"msg,omitempty"`
	} `json:"meta"`
	Data []syncTestRecord `json:"data"`
}

type syncTestController struct {
	mutex        sync.Mutex
	user         string
	pass         string
	session      string
	records      []syncTestRecord
	deniedLogins int
}

func (controller *syncTestController) serve(writer http.ResponseWriter, request *http.Request) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()
	response := syncTestEnvelope{}
	response.Meta.Result = "ok"
	writer.Header().Set("Content-Type", "application/json")

	if request.URL.Path == "/api/login" {
		var credentials struct {
			User string `json:"username"`
			Pass string `json:"password"`
		}
		if err := json.NewDecoder(request.Body).Decode(&credentials); err != nil ||
			credentials.User != controller.user || credentials.Pass != controller.pass {
			controller.deniedLogins++
			response.Meta.Result = "error"
			response.Meta.Message = "authentication denied"
			writer.WriteHeader(http.StatusUnauthorized)
		} else {
			http.SetCookie(
				writer,
				&http.Cookie{
					Name:  "sync-session",
					Value: controller.session,
					Path:  "/",
				},
			)
			writer.Header().Set("X-Csrf-Token", controller.session)
		}

		if err := json.NewEncoder(writer).Encode(response); err != nil {
			panic(err)
		}

		return
	}

	cookie, err := request.Cookie("sync-session")
	if err != nil || cookie.Value != controller.session ||
		request.Header.Get("X-Csrf-Token") != controller.session {
		writer.WriteHeader(http.StatusUnauthorized)

		return
	}

	const collectionPath = "/api/s/default/rest/networkconf"
	switch {
	case request.Method == http.MethodGet && request.URL.Path == collectionPath:
		response.Data = controller.records
	case request.Method == http.MethodPut && strings.HasPrefix(
		request.URL.Path,
		collectionPath+"/",
	):
		var record syncTestRecord
		if err := json.NewDecoder(request.Body).Decode(&record); err != nil {
			writer.WriteHeader(http.StatusBadRequest)

			return
		}

		for index, existing := range controller.records {
			if request.URL.Path != collectionPath+"/"+existing.ID {
				continue
			}

			record.ID = existing.ID
			controller.records[index] = record
			response.Data = []syncTestRecord{record}
		}
	case request.Method == http.MethodDelete && len(controller.records) == 1 &&
		request.URL.Path == collectionPath+"/"+controller.records[0].ID:
		controller.records = nil
	default:
		writer.WriteHeader(http.StatusNotFound)

		return
	}

	if err := json.NewEncoder(writer).Encode(response); err != nil {
		panic(err)
	}
}

func (controller *syncTestController) snapshot() ([]syncTestRecord, int) {
	controller.mutex.Lock()
	defer controller.mutex.Unlock()

	return append([]syncTestRecord(nil), controller.records...), controller.deniedLogins
}

func TestSyncCLIUsesCredentialFilesAndPreservesPullPushControls(t *testing.T) {
	controller := &syncTestController{
		user:    rand.Text(),
		pass:    rand.Text(),
		session: rand.Text(),
		records: []syncTestRecord{{ID: "office", Name: "Office", VLAN: 10}},
	}
	server := httptest.NewServer(http.HandlerFunc(controller.serve))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	userPath := filepath.Join(directory, "username")
	passPath := filepath.Join(directory, "password")
	if err := os.WriteFile(userPath, []byte(controller.user+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(passPath, []byte(controller.pass+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	storePath := filepath.Join(directory, "records")
	command := func(direction string, flags ...string) error {
		arguments := []string{
			"sync",
			direction,
			"--controller-url",
			server.URL,
			"--username-file",
			userPath,
			"--password-file",
			passPath,
			"--dir",
			storePath,
			"--collections",
			"networkconf",
		}
		var output bytes.Buffer

		return run(t.Context(), append(arguments, flags...), &output)
	}
	if err := command("pull"); err != nil {
		t.Fatal(err)
	}

	store, err := syncstore.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}

	collection, present := unifiapi.Lookup("networkconf")
	if !present {
		t.Fatal("The network configuration collection does not exist.")
	}

	records, err := store.Read("default", collection)
	if err != nil || len(records) != 1 {
		t.Fatal("The pull command did not store the controller record.")
	}

	name, present := records[0].Text("name")
	if !present || name != "Office" || string(records[0]["vlan"]) != "10" {
		t.Fatal("The stored record does not contain the controller configuration.")
	}

	records[0]["vlan"] = json.RawMessage(strconv.Itoa(20))
	if err := store.Write("default", collection, records); err != nil {
		t.Fatal(err)
	}

	if err := command("push", "--dry-run"); err != nil {
		t.Fatal(err)
	}

	remote, _ := controller.snapshot()
	if len(remote) != 1 || remote[0].VLAN != 10 {
		t.Fatal("The dry run changed the controller record.")
	}

	if err := command("push"); err != nil {
		t.Fatal(err)
	}

	remote, _ = controller.snapshot()
	if len(remote) != 1 || remote[0].VLAN != 20 {
		t.Fatal("The push command did not update the controller record.")
	}

	if err := store.Write("default", collection, nil); err != nil {
		t.Fatal(err)
	}

	if err := command("push"); err != nil {
		t.Fatal(err)
	}

	remote, _ = controller.snapshot()
	if len(remote) != 1 {
		t.Fatal("The push command removed a record without the prune flag.")
	}

	if err := command("push", "--prune"); err != nil {
		t.Fatal(err)
	}

	remote, _ = controller.snapshot()
	if len(remote) != 0 {
		t.Fatal("The prune command did not remove the destination record.")
	}

	if err := os.WriteFile(passPath, []byte(rand.Text()), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := command("pull"); err == nil ||
		!strings.Contains(err.Error(), "authentication denied") {
		t.Fatal("The command did not reject an incorrect credential file.")
	}

	_, denied := controller.snapshot()
	if denied != 1 {
		t.Fatal("The controller did not validate the credential file contents.")
	}
}
