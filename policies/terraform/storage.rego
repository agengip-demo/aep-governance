# Rule `storage`: no public blob access, TLS 1.2 or newer.
package main

import rego.v1

allowed_tls_versions := {"TLS1_2", "TLS1_3"}

deny contains msg if {
	some rc in planned_resources
	rc.type == "azurerm_storage_account"
	after_attr(rc, "allow_nested_items_to_be_public") != false
	msg := denial(
		"storage",
		rc.address,
		"the storage account allows public blob access.",
		"set `allow_nested_items_to_be_public = false`.",
	)
}

deny contains msg if {
	some rc in planned_resources
	rc.type == "azurerm_storage_account"
	tls := after_attr(rc, "min_tls_version")
	not tls in allowed_tls_versions
	msg := denial(
		"storage",
		rc.address,
		sprintf("min_tls_version is %v, which allows TLS below 1.2.", [tls]),
		"set `min_tls_version = \"TLS1_2\"`.",
	)
}

deny contains msg if {
	some rc in planned_resources
	rc.type == "azurerm_storage_container"
	access := after_attr(rc, "container_access_type")
	is_string(access)
	access != "private"
	msg := denial(
		"storage",
		rc.address,
		sprintf("container_access_type %q makes blobs public.", [access]),
		"set `container_access_type = \"private\"`.",
	)
}
