package syncstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goodkind.io/unifi-go/internal/unifiapi"
)

func wlanconf(t *testing.T) unifiapi.Collection {
	t.Helper()
	collection, found := unifiapi.Lookup("wlanconf")
	if !found {
		t.Fatal("wlanconf collection is missing from the registry")
	}
	return collection
}

func record(t *testing.T, body string) unifiapi.Record {
	t.Helper()
	var result unifiapi.Record
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return result
}

func TestStore_WriteThenReadReturnsTheSameRecords(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "controller"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	collection := wlanconf(t)
	written := []unifiapi.Record{
		record(t, `{"name":"LebaneseRocketSociety","enabled":true,"wlan_bands":["2g","5g"],"pmf_mode":"required"}`),
		record(t, `{"name":"Guest Wi-Fi/2","enabled":false,"wlan_bands":["2g"],"pmf_mode":"disabled"}`),
	}

	if err := store.Write("default", collection, written); err != nil {
		t.Fatalf("write records: %v", err)
	}

	read, err := store.Read("default", collection)
	if err != nil {
		t.Fatalf("read records: %v", err)
	}
	if len(read) != 2 {
		t.Fatalf("read %d records, want 2", len(read))
	}
	if name, _ := read[0].Text("name"); name != "Guest Wi-Fi/2" {
		t.Fatalf("first record is %q, want the identity-ordered %q", name, "Guest Wi-Fi/2")
	}
	mode, _ := read[1].Text("pmf_mode")
	if mode != "required" {
		t.Fatalf("pmf_mode read back as %q, want required", mode)
	}
}

func TestStore_WriteRemovesRecordsTheSourceDropped(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller")
	store, err := Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	collection := wlanconf(t)
	both := []unifiapi.Record{
		record(t, `{"name":"Keep","enabled":true}`),
		record(t, `{"name":"Drop","enabled":true}`),
	}
	if err := store.Write("default", collection, both); err != nil {
		t.Fatalf("write both records: %v", err)
	}

	if err := store.Write("default", collection, both[:1]); err != nil {
		t.Fatalf("write one record: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(root, "default", "wlanconf"))
	if err != nil {
		t.Fatalf("read collection directory: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "Keep.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("directory holds %v, want only Keep.json", names)
	}
}

func TestStore_WriteProducesStableSortedFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller")
	store, err := Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	collection := wlanconf(t)
	written := []unifiapi.Record{
		record(t, `{"wlan_bands":["2g","5g"],"name":"Lab","enabled":true,"radio_table":[{"ht":"20","channel":6}]}`),
	}

	if err := store.Write("default", collection, written); err != nil {
		t.Fatalf("write record: %v", err)
	}

	path := filepath.Join(root, "default", "wlanconf", "Lab.json")
	first, err := os.ReadFile(path) // #nosec G304 -- test-owned temporary path
	if err != nil {
		t.Fatalf("read record file: %v", err)
	}
	if err := store.Write("default", collection, written); err != nil {
		t.Fatalf("rewrite record: %v", err)
	}
	second, err := os.ReadFile(path) // #nosec G304 -- test-owned temporary path
	if err != nil {
		t.Fatalf("reread record file: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("a second write changed the file:\n%s\n%s", first, second)
	}
	text := string(first)
	if strings.Index(text, `"enabled"`) > strings.Index(text, `"name"`) {
		t.Fatalf("members are not sorted:\n%s", text)
	}
	if !strings.Contains(text, "\n      \"channel\": 6") {
		t.Fatalf("nested members are not indented:\n%s", text)
	}
}

func TestStore_WriteEncodesIdentityCharactersThatFileNamesReject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "controller")
	store, err := Open(root)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	collection, found := unifiapi.Lookup("device")
	if !found {
		t.Fatal("device collection is missing from the registry")
	}

	if err := store.Write("default", collection, []unifiapi.Record{record(t, `{"mac":"80:2a:a8:86:97:0d","name":"AC Pro"}`)}); err != nil {
		t.Fatalf("write device record: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(root, "default", "device"))
	if err != nil {
		t.Fatalf("read device directory: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("wrote %d files, want 1", len(entries))
	}
	if strings.Contains(entries[0].Name(), ":") {
		t.Fatalf("file name %q keeps a character some file systems reject", entries[0].Name())
	}
	read, err := store.Read("default", collection)
	if err != nil {
		t.Fatalf("read device records: %v", err)
	}
	if mac, _ := read[0].Text("mac"); mac != "80:2a:a8:86:97:0d" {
		t.Fatalf("read back %q, want the original hardware address", mac)
	}
}
