package main

import rego.v1

test_location_outside_allowed_list_is_denied if {
	after := object.union(good_storage_after, {"location": "eastus"})
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_account", "exports", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[location] azurerm_storage_account.exports: ")
	contains(m, "\"eastus\"")
	contains(m, "Required change: ")
	contains(m, "swedencentral")
}

test_location_display_name_is_normalised if {
	after := object.union(good_storage_after, {"location": "Sweden Central"})
	count(deny) == 0 with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
}

test_location_computed_for_container_app_is_accepted if {
	# Container apps have no location argument; it is computed from their environment.
	r := mk_rc("azurerm_container_app", "app", ["create"], good_app_after)
	r2 := object.union(r, {"change": {"after_unknown": {"location": true}}})
	count(deny) == 0 with input as mk_plan([r2])
}

test_location_unknown_is_denied if {
	# Fail closed: a location that is only known after apply cannot be checked.
	after := object.remove(good_storage_after, ["location"])
	r := mk_rc("azurerm_storage_account", "st", ["create"], after)
	r2 := object.union(r, {"change": {"after_unknown": {"location": true}}})
	msgs := deny with input as mk_plan([r2])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[location] azurerm_storage_account.st: ")
	contains(m, "only known after apply")
	contains(m, "Required change: ")
}

test_location_list_comes_from_profile if {
	after := object.union(good_storage_after, {"location": "eastus"})
	count(deny) == 0 with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
		with data.cloud.allowed_locations as ["eastus"]
}
