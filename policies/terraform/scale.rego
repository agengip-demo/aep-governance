# Rule `scale`: a container app allows at most cloud.max_container_replicas replicas.
package main

import rego.v1

deny contains msg if {
	some rc in planned_resources
	rc.type == "azurerm_container_app"
	some tpl in object.get(rc.change.after, "template", [])
	max_r := object.get(tpl, "max_replicas", null)
	is_number(max_r)
	max_r > data.cloud.max_container_replicas
	msg := denial(
		"scale",
		rc.address,
		sprintf("template.max_replicas = %v exceeds the limit.", [max_r]),
		sprintf("set `template { max_replicas = ... }` to at most %v.", [data.cloud.max_container_replicas]),
	)
}

deny contains msg if {
	some rc in planned_resources
	rc.type == "azurerm_container_app"
	some tpl in object.get(rc.change.after, "template", [])
	not is_number(object.get(tpl, "max_replicas", null))
	msg := denial(
		"scale",
		rc.address,
		"template.max_replicas is not set, so the service default (more than the limit) applies.",
		sprintf("set `template { max_replicas = ... }` explicitly to at most %v.", [data.cloud.max_container_replicas]),
	)
}

deny contains msg if {
	some rc in planned_resources
	rc.type == "azurerm_container_app"
	some tpl in object.get(rc.change.after, "template", [])
	min_r := object.get(tpl, "min_replicas", null)
	is_number(min_r)
	min_r > data.cloud.max_container_replicas
	msg := denial(
		"scale",
		rc.address,
		sprintf("template.min_replicas = %v exceeds the limit.", [min_r]),
		sprintf("set `template { min_replicas = 0 }` (at most %v).", [data.cloud.max_container_replicas]),
	)
}
