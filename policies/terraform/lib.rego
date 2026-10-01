# Shared helpers for the Terraform plan policies.
#
# Input: the output of `terraform show -json <planfile>`.
# Data:  the rule profile (profiles/demo.yaml), passed with `conftest --data profiles`,
#        so thresholds live at data.cloud.* and are never hard-coded here.
package main

import rego.v1

# Managed resources that exist after apply: create, update, replace and no-op.
# Pure deletions and data sources are not checked.
planned_resources contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	not delete_only(rc)
}

delete_only(rc) if rc.change.actions == ["delete"]

# Every message names the rule, the resource address and the required change,
# because the coding agent reads it and acts on it.
denial(rule, address, problem, fix) := sprintf("[%s] %s: %s Required change: %s", [rule, address, problem, fix])

# Value of an attribute after apply, or null when it is absent or unknown.
after_attr(rc, name) := object.get(object.get(rc.change, "after", {}), name, null)

# True when the attribute is only known after apply.
after_unknown(rc, name) if object.get(object.get(rc.change, "after_unknown", {}), name, false) == true
