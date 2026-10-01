package main

import rego.v1

# Test helpers: build minimal `terraform show -json` plan documents.

mk_plan(changes) := {"format_version": "1.2", "resource_changes": changes}

mk_rc(type, name, actions, after) := {
	"address": sprintf("%s.%s", [type, name]),
	"mode": "managed",
	"type": type,
	"name": name,
	"change": {"actions": actions, "after": after, "after_unknown": {}},
}

good_tags := {
	"project": "demo1",
	"environment": "dev",
	"owner": "octocat",
	"managed-by": "aep",
}

good_app_after := {
	"name": "ca-demo1-dev",
	"tags": good_tags,
	"template": [{"min_replicas": 0, "max_replicas": 2}],
}

good_storage_after := {
	"name": "stdemo1dev",
	"location": "swedencentral",
	"tags": good_tags,
	"allow_nested_items_to_be_public": false,
	"min_tls_version": "TLS1_2",
}

test_helper_messages_name_rule_address_and_fix if {
	msg := denial("tags", "azurerm_container_app.app", "problem.", "do this.")
	msg == "[tags] azurerm_container_app.app: problem. Required change: do this."
}

test_compliant_plan_has_no_denials if {
	p := mk_plan([
		mk_rc("azurerm_container_app", "app", ["create"], good_app_after),
		mk_rc("azurerm_storage_account", "exports", ["create"], good_storage_after),
	])
	count(deny) == 0 with input as p
}

test_deleted_resources_are_ignored if {
	p := mk_plan([mk_rc("azurerm_virtual_machine", "old", ["delete"], null)])
	count(deny) == 0 with input as p
}

test_data_sources_are_ignored if {
	r := object.union(mk_rc("azurerm_resource_group", "rg", ["read"], {"location": "eastus"}), {"mode": "data"})
	count(deny) == 0 with input as mk_plan([r])
}

test_empty_plan_has_no_denials if {
	count(deny) == 0 with input as {"format_version": "1.2"}
}

# Replace one attribute (object.union would merge nested objects).
with_attr(obj, key, value) := object.union(object.remove(obj, [key]), {key: value})
