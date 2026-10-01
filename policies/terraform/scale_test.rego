package main

import rego.v1

test_scale_too_many_replicas_denied if {
	after := object.union(good_app_after, {"template": [{"min_replicas": 0, "max_replicas": 5}]})
	msgs := deny with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	startswith(m, "[scale] azurerm_container_app.app: ")
	contains(m, "max_replicas = 5")
	contains(m, "Required change: ")
	contains(m, "at most 2")
}

test_scale_unset_max_replicas_denied if {
	after := object.union(good_app_after, {"template": [{"min_replicas": 0}]})
	msgs := deny with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	contains(m, "[scale]")
	contains(m, "not set")
}

test_scale_min_above_limit_denied if {
	after := object.union(good_app_after, {"template": [{"min_replicas": 3, "max_replicas": 2}]})
	msgs := deny with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
	count(msgs) == 1
	some m in msgs
	contains(m, "min_replicas = 3")
}

test_scale_limit_comes_from_profile if {
	after := object.union(good_app_after, {"template": [{"min_replicas": 0, "max_replicas": 5}]})
	count(deny) == 0 with input as mk_plan([mk_rc("azurerm_container_app", "app", ["create"], after)])
		with data.cloud.max_container_replicas as 5
}
