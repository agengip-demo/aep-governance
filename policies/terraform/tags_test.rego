package main

import rego.v1

test_tags_missing_all_when_tags_null if {
	after := object.union(good_app_after, {"tags": null})
	msgs := deny with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[tags] azurerm_container_app.app: ")
	contains(m, "managed-by")
	contains(m, "Required change: ")
	contains(m, "local.tags")
}

test_tags_missing_one if {
	tags := object.remove(good_tags, ["owner"])
	after := with_attr(good_storage_after, "tags", tags)
	msgs := deny with input as mk_plan([mk_rc("azurerm_storage_account", "st", ["update"], after)])
	count(msgs) == 1
	some m in msgs
	contains(m, "[tags] azurerm_storage_account.st")
	contains(m, "missing required tags [\"owner\"]")
}

test_tags_empty_value_counts_as_missing if {
	tags := object.union(good_tags, {"project": ""})
	after := with_attr(good_app_after, "tags", tags)
	msgs := deny with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
	some m in msgs
	contains(m, "missing required tags [\"project\"]")
}

# Fail closed: a tag that is only known after apply cannot be checked.
test_tags_unknown_value_is_denied if {
	tags := object.remove(good_tags, ["owner"])
	after := with_attr(good_app_after, "tags", tags)
	r := mk_rc("azurerm_container_app", "app", ["create"], after)
	r2 := object.union(r, {"change": {"after_unknown": {"tags": {"owner": true}}}})
	msgs := deny with input as mk_plan([r2])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[tags] azurerm_container_app.app: ")
	contains(m, "only known after apply")
	contains(m, "\"owner\"")
}

test_tags_fully_unknown_is_denied if {
	after := object.remove(good_app_after, ["tags"])
	r := mk_rc("azurerm_container_app", "app", ["create"], after)
	r2 := object.union(r, {"change": {"after_unknown": {"tags": true}}})
	msgs := deny with input as mk_plan([r2])
	count(msgs) == 1
	some m in msgs
	contains(m, "only known after apply")
}

test_tags_resources_without_tags_attribute_are_skipped if {
	after := {"name": "exports", "container_access_type": "private"}
	count(deny) == 0 with input as mk_plan([mk_rc("azurerm_storage_container", "c", ["create"], after)])
}

test_tags_required_list_comes_from_profile if {
	after := with_attr(good_app_after, "tags", {"cost-center": "x"})
	msgs := deny with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
		with data.cloud.required_tags as ["cost-center"]
	count(msgs) == 0
}
