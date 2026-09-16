package syncplan

import (
	"bytes"
	"encoding/json"
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

func render(t *testing.T, plan Plan) string {
	t.Helper()
	output := new(bytes.Buffer)
	if err := Render(output, plan); err != nil {
		t.Fatalf("render plan: %v", err)
	}
	return output.String()
}

func TestCompare_MatchingRecordsNeedNoWork(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"name":"Lab","enabled":true,"wlan_bands":["2g","5g"]}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","site_id":"aa11","name":"Lab","enabled":true,"wlan_bands":["2g","5g"]}`)}

	plan, err := Compare(collection, source, destination, true)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	if !plan.Empty() {
		t.Fatalf("identical policy produced work:\n%s", render(t, plan))
	}
}

func TestCompare_ArrayOrderIsPartOfTheValue(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"name":"Lab","wlan_bands":["5g","2g"]}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","name":"Lab","wlan_bands":["2g","5g"]}`)}

	plan, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	text := render(t, plan)
	if !strings.Contains(text, `update "Lab"`) {
		t.Fatalf("plan does not update the record:\n%s", text)
	}
	if !strings.Contains(text, `wlan_bands: ["2g","5g"] -> ["5g","2g"]`) {
		t.Fatalf("plan does not name the band order change:\n%s", text)
	}
}

func TestCompare_UpdateKeepsTheDestinationIdentifierAndUnmanagedFields(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"name":"Lab","pmf_mode":"required"}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","site_id":"aa11","name":"Lab","pmf_mode":"disabled","usergroup_id":"77bb"}`)}

	plan, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	if len(plan.Changes) != 1 {
		t.Fatalf("plan holds %d changes, want 1", len(plan.Changes))
	}
	change := plan.Changes[0]
	if change.ID != "64f0" {
		t.Fatalf("change carries identifier %q, want the destination identifier", change.ID)
	}
	if group, _ := change.Record.Text("usergroup_id"); group != "77bb" {
		t.Fatalf("the written record dropped usergroup_id, leaving %q", group)
	}
	if mode, _ := change.Record.Text("pmf_mode"); mode != "required" {
		t.Fatalf("the written record carries pmf_mode %q, want required", mode)
	}
}

func TestCompare_PruneControlsWhetherExtraRecordsDisappear(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"name":"Lab"}`)}
	destination := []unifiapi.Record{
		record(t, `{"_id":"64f0","name":"Lab"}`),
		record(t, `{"_id":"64f1","name":"Retired"}`),
	}

	kept, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare without prune: %v", err)
	}
	if !kept.Empty() {
		t.Fatalf("a comparison without prune proposed work:\n%s", render(t, kept))
	}

	pruned, err := Compare(collection, source, destination, true)
	if err != nil {
		t.Fatalf("compare with prune: %v", err)
	}
	created, updated, deleted := pruned.Counts()
	if created != 0 || updated != 0 || deleted != 1 {
		t.Fatalf("prune produced %d creates, %d updates, %d deletes; want one delete", created, updated, deleted)
	}
	if pruned.Changes[0].ID != "64f1" {
		t.Fatalf("delete targets %q, want the retired record", pruned.Changes[0].ID)
	}
}

func TestCompare_CreateCarriesPolicyWithoutControllerAssignedFields(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"_id":"aaaa","site_id":"bbbb","x_iapp_key":"cccc","name":"Lab","enabled":true}`)}

	plan, err := Compare(collection, source, nil, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	if len(plan.Changes) != 1 || plan.Changes[0].Action != ActionCreate {
		t.Fatalf("plan is %v, want one create", plan.Changes)
	}
	written := plan.Changes[0].Record
	for _, field := range []string{"_id", "site_id", "x_iapp_key"} {
		if _, present := written[field]; present {
			t.Fatalf("the created record carries the controller-assigned field %q", field)
		}
	}
	if name, _ := written.Text("name"); name != "Lab" {
		t.Fatalf("the created record is named %q, want Lab", name)
	}
}

func TestRender_ShowsThatASecretChangedWithoutPrintingIt(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"name":"Lab","x_passphrase":"replacement-secret","auth_servers":[{"ip":"10.0.0.1","x_secret":"nested-secret"}]}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","name":"Lab","x_passphrase":"original-secret","auth_servers":[{"ip":"10.0.0.1","x_secret":"other-secret"}]}`)}

	plan, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	text := render(t, plan)
	for _, secret := range []string{"replacement-secret", "original-secret", "nested-secret", "other-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("the rendered plan printed the secret %q:\n%s", secret, text)
		}
	}
	if strings.Count(text, "sha256:") != 4 {
		t.Fatalf("the rendered plan does not digest both secrets on both sides:\n%s", text)
	}
	if !strings.Contains(text, "x_passphrase: ") || !strings.Contains(text, "x_secret") {
		t.Fatalf("the rendered plan hides which field changed:\n%s", text)
	}
}

func TestRender_KeepsANonSecretFlagBesideACredentialNameReadable(t *testing.T) {
	collection := wlanconf(t)
	source := []unifiapi.Record{record(t, `{"name":"Lab","passphrase_autogenerated":true}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","name":"Lab","passphrase_autogenerated":false}`)}

	plan, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	text := render(t, plan)
	if !strings.Contains(text, "passphrase_autogenerated: false -> true") {
		t.Fatalf("a boolean beside a credential name was hidden:\n%s", text)
	}
}

func TestCompare_DeviceComparisonIgnoresLiveCounters(t *testing.T) {
	collection, found := unifiapi.Lookup("device")
	if !found {
		t.Fatal("device collection is missing from the registry")
	}
	source := []unifiapi.Record{record(t, `{"mac":"80:2a:a8:86:97:0d","name":"AC Pro","uptime":319904,"rx_bytes":881,"radio_table":[{"name":"wifi0","channel":6}]}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","mac":"80:2a:a8:86:97:0d","name":"AC Pro","uptime":12,"rx_bytes":4410229,"radio_table":[{"name":"wifi0","channel":6}]}`)}

	plan, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	if !plan.Empty() {
		t.Fatalf("live counters produced work:\n%s", render(t, plan))
	}
}

func TestCompare_DeviceComparisonSeesRadioPolicy(t *testing.T) {
	collection, found := unifiapi.Lookup("device")
	if !found {
		t.Fatal("device collection is missing from the registry")
	}
	source := []unifiapi.Record{record(t, `{"mac":"80:2a:a8:86:97:0d","radio_table":[{"name":"wifi1","channel":44,"ht":"40"}]}`)}
	destination := []unifiapi.Record{record(t, `{"_id":"64f0","mac":"80:2a:a8:86:97:0d","radio_table":[{"name":"wifi1","channel":"auto","ht":"40"}]}`)}

	plan, err := Compare(collection, source, destination, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	text := render(t, plan)
	if !strings.Contains(text, `"channel":44`) {
		t.Fatalf("the plan does not name the channel change:\n%s", text)
	}
}

func TestCompare_RejectsARecordWithoutItsIdentity(t *testing.T) {
	collection := wlanconf(t)

	_, err := Compare(collection, []unifiapi.Record{record(t, `{"enabled":true}`)}, nil, false)

	if err == nil {
		t.Fatal("a record without a name compared successfully")
	}
	if !strings.Contains(err.Error(), "without a name") {
		t.Fatalf("error is %q, want it to name the missing identity", err)
	}
}

func TestRender_DigestsOneValueTheSameWayOnBothSides(t *testing.T) {
	collection := wlanconf(t)
	compact := []unifiapi.Record{record(t, `{"name":"Lab","x_ssh_keys":[{"name":"one","key":"AAAA"}]}`)}
	spaced := []unifiapi.Record{record(t, `{"_id":"64f0","name":"Lab","x_ssh_keys":[ { "key" : "AAAA" , "name" : "one" } ]}`)}

	plan, err := Compare(collection, compact, spaced, false)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}

	if !plan.Empty() {
		t.Fatalf("the same key spelled two ways produced work:\n%s", render(t, plan))
	}

	changed := []unifiapi.Record{record(t, `{"_id":"64f0","name":"Lab","x_ssh_keys":[{"name":"two","key":"BBBB"}]}`)}
	plan, err = Compare(collection, compact, changed, false)
	if err != nil {
		t.Fatalf("compare changed key: %v", err)
	}
	text := render(t, plan)
	digests := strings.Count(text, "sha256:")
	if digests != 2 {
		t.Fatalf("a replaced key rendered %d digests, want one for each side:\n%s", digests, text)
	}
	before, after, found := strings.Cut(strings.SplitN(text, "x_ssh_keys: ", 2)[1], " -> ")
	if !found || before == after {
		t.Fatalf("a replaced key rendered the same digest on both sides:\n%s", text)
	}
}
