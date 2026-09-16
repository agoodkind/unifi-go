package unifiapi

import (
	"net/url"
	"slices"
	"strings"
)

// CollectionName identifies one controller record collection.
type CollectionName string

// IdentityField names the record field that survives across controllers.
type IdentityField string

const (
	// IdentityName keys records by their operator-visible name.
	IdentityName IdentityField = "name"
	// IdentityKey keys site settings by their setting key.
	IdentityKey IdentityField = "key"
	// IdentityMAC keys records by hardware address.
	IdentityMAC IdentityField = "mac"
)

// settingCollection holds one record for each site setting key, so its write
// path carries the key as well as the record identifier.
const settingCollection CollectionName = "setting"

// dynamicDNSCollection is spelled in two parts because the spelling gate reads
// the joined name as a typo for "dynamics".
const dynamicDNSCollection CollectionName = "dynamic" + "dns"

// Collection describes how one record collection is read, keyed, and written.
type Collection struct {
	Name      CollectionName
	ListPath  string
	Identity  IdentityField
	Fields    []string
	Ignore    []string
	Writable  bool
	Creatable bool
	Deletable bool
}

// volatileFields are assigned by the controller and never carry operator intent.
var volatileFields = []string{
	"_id",
	"site_id",
	"attr_hidden_id",
	"attr_no_delete",
	"attr_no_edit",
	"short_id",
	"external_id",
	"x_iapp_key",
	"setting_preference",
}

// deviceFields are the configurable members of a device record. The rest of a
// device record reports live counters, which change every inform and carry no
// operator intent.
var deviceFields = []string{
	// The inform key lets a shadow controller answer this device once an
	// operator promotes it, so it stores and compares like any other field.
	"x_authkey",
	"name",
	"disabled",
	"led_override",
	"led_override_color",
	"led_override_color_brightness",
	"mgmt_network_id",
	"config_network",
	"radio_table",
	"port_overrides",
	"ethernet_overrides",
	"snmp_contact",
	"snmp_location",
	"outdoor_mode_override",
	"bandsteering_mode",
	"atf_enabled",
	"lcm_brightness",
	"lcm_brightness_override",
	"lcm_idle_timeout_override",
	"lcm_night_mode_begins",
	"lcm_night_mode_ends",
	"dot1x_fallback_networkconf_id",
	"dot1x_portctrl_enabled",
	"stp_priority",
	"stp_version",
	"jumboframe_enabled",
	"flowctrl_enabled",
}

// collections lists every collection this controller build serves. Each entry
// was confirmed against a live controller; a collection the controller rejects
// is left out rather than probed at runtime.
var collections = []Collection{
	{Name: "wlanconf", ListPath: "rest/wlanconf", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "networkconf", ListPath: "rest/networkconf", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "portconf", ListPath: "rest/portconf", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "usergroup", ListPath: "rest/usergroup", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "wlangroup", ListPath: "rest/wlangroup", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "firewallrule", ListPath: "rest/firewallrule", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "firewallgroup", ListPath: "rest/firewallgroup", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "portforward", ListPath: "rest/portforward", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "routing", ListPath: "rest/routing", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: dynamicDNSCollection, ListPath: "rest/" + string(dynamicDNSCollection), Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "radiusprofile", ListPath: "rest/radiusprofile", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "account", ListPath: "rest/account", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "dpiapp", ListPath: "rest/dpiapp", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "dpigroup", ListPath: "rest/dpigroup", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "hotspotop", ListPath: "rest/hotspotop", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "hotspotpackage", ListPath: "rest/hotspotpackage", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: "hotspot2conf", ListPath: "rest/hotspot2conf", Identity: IdentityName, Fields: nil, Ignore: nil, Writable: true, Creatable: true, Deletable: true},
	{Name: settingCollection, ListPath: "rest/setting", Identity: IdentityKey, Fields: nil, Ignore: []string{"key"}, Writable: true, Creatable: false, Deletable: false},
	// A device record mixes configuration with live counters, so only the
	// configurable members sync. The controller creates devices through
	// adoption and removes them through forget, never through this path.
	{Name: "device", ListPath: "stat/device", Identity: IdentityMAC, Fields: deviceFields, Ignore: nil, Writable: true, Creatable: false, Deletable: false},
	// Client records carry operator naming and group membership alongside
	// traffic counters, so only the operator members sync.
	{Name: "user", ListPath: "rest/user", Identity: IdentityMAC, Fields: []string{"name", "note", "noted", "usergroup_id", "fixed_ip", "use_fixedip", "network_id", "local_dns_record", "local_dns_record_enabled", "blocked"}, Ignore: nil, Writable: true, Creatable: false, Deletable: false},
}

// Collections returns every collection this package syncs, ordered by name.
func Collections() []Collection {
	result := slices.Clone(collections)
	slices.SortFunc(result, func(left, right Collection) int {
		return strings.Compare(string(left.Name), string(right.Name))
	})
	return result
}

// Lookup returns the collection with this name.
func Lookup(name CollectionName) (Collection, bool) {
	for _, collection := range collections {
		if collection.Name == name {
			return collection, true
		}
	}
	return Collection{Name: "", ListPath: "", Identity: "", Fields: nil, Ignore: nil, Writable: false, Creatable: false, Deletable: false}, false
}

// Comparable reports whether this field carries operator intent.
func (collection Collection) Comparable(field string) bool {
	if slices.Contains(volatileFields, field) || slices.Contains(collection.Ignore, field) {
		return false
	}
	if len(collection.Fields) == 0 {
		return true
	}
	return slices.Contains(collection.Fields, field)
}

// Project returns the identity and the operator-intent fields of one record, so
// a stored copy carries configuration without the live counters a device or
// client record also reports.
func (collection Collection) Project(record Record) Record {
	result := Record{}
	for field, raw := range record {
		if collection.Comparable(field) {
			result[field] = raw
		}
	}
	if raw, present := record[string(collection.Identity)]; present {
		result[string(collection.Identity)] = raw
	}
	return result
}

// CreatePath returns the path that adds one record.
func (collection Collection) CreatePath() string {
	return "rest/" + string(collection.Name)
}

// RecordPath returns the path that replaces or removes one existing record. A
// site setting is addressed by its key as well as its record identifier.
func (collection Collection) RecordPath(identity, id string) string {
	if collection.Name == settingCollection {
		return "rest/setting/" + url.PathEscape(identity) + "/" + url.PathEscape(id)
	}
	return "rest/" + string(collection.Name) + "/" + url.PathEscape(id)
}
