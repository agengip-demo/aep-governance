package main

import rego.v1

test_storage_public_nested_items_denied if {
	after := object.union(good_storage_after, {"allow_nested_items_to_be_public": true})
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[storage] azurerm_storage_account.st: ")
	contains(m, "allow_nested_items_to_be_public = false")
}

test_storage_public_access_unset_is_denied if {
	after := object.remove(good_storage_after, ["allow_nested_items_to_be_public"])
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
	count(msgs) == 1
}

test_storage_old_tls_denied if {
	after := object.union(good_storage_after, {"min_tls_version": "TLS1_0"})
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[storage] azurerm_storage_account.st: ")
	contains(m, "TLS1_0")
	contains(m, "min_tls_version = \"TLS1_2\"")
}

test_storage_tls13_allowed if {
	after := object.union(good_storage_after, {"min_tls_version": "TLS1_3"})
	count(deny) == 0 with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
}

test_storage_both_problems_give_two_messages if {
	after := object.union(good_storage_after, {"allow_nested_items_to_be_public": true, "min_tls_version": "TLS1_1"})
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["create"], after)])
	count(msgs) == 2
}

test_storage_public_container_denied if {
	after := {"name": "exports", "container_access_type": "blob"}
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_container", "c", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[storage] azurerm_storage_container.c: ")
	contains(m, "container_access_type = \"private\"")
}

test_storage_private_container_allowed if {
	after := {"name": "exports", "container_access_type": "private"}
	count(deny) == 0 with input as mk_plan([mk_rc("azurerm_storage_container", "c", ["create"], after)])
}
