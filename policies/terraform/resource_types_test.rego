package main

import rego.v1

test_resource_type_not_allowed_is_denied if {
	after := {"name": "vm1", "location": "swedencentral", "tags": good_tags}
	msgs := deny with input as mk_plan([mk_rc("azurerm_linux_virtual_machine", "vm", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[resource_types] azurerm_linux_virtual_machine.vm: ")
	contains(m, "Required change: ")
	contains(m, "azurerm_container_app")
}

test_resource_type_in_module_reports_full_address if {
	r := object.union(
		mk_rc("azurerm_public_ip", "ip", ["create"], {"location": "swedencentral", "tags": good_tags}),
		{"address": "module.net.azurerm_public_ip.ip", "module_address": "module.net"},
	)
	msgs := deny with input as mk_plan([r])
	some m in msgs
	startswith(m, "[resource_types] module.net.azurerm_public_ip.ip: ")
}

test_resource_type_noop_existing_resource_still_checked if {
	msgs := deny with input as mk_plan([mk_rc("null_resource", "x", ["no-op"], {"id": "1"})])
	count(msgs) == 1
}

test_resource_type_list_comes_from_profile if {
	count(deny) == 0 with input as mk_plan([mk_rc("null_resource", "x", ["create"], {"id": "1"})])
		with data.cloud.allowed_resource_types as ["null_resource"]
}
