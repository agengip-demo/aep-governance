# Rule `location`: resources only in cloud.allowed_locations.
package main

import rego.v1

deny contains msg if {
	some rc in planned_resources
	loc := after_attr(rc, "location")
	is_string(loc)
	not location_allowed(loc)
	msg := denial(
		"location",
		rc.address,
		sprintf("location %q is not allowed.", [loc]),
		sprintf("set `location` to one of %v (use var.location where the module has it).", [data.cloud.allowed_locations]),
	)
}

# Fail closed: a location only known after apply cannot be checked. Types whose
# location is a computed attribute only (no argument) are exempt.
computed_location_types := {"azurerm_container_app"}

deny contains msg if {
	some rc in planned_resources
	after_unknown(rc, "location")
	not rc.type in computed_location_types
	msg := denial(
		"location",
		rc.address,
		"the location is only known after apply, so it cannot be checked.",
		sprintf("set `location` to a value known at plan time, one of %v (e.g. var.location).", [data.cloud.allowed_locations]),
	)
}

location_allowed(loc) if {
	some allowed in data.cloud.allowed_locations
	normalize_location(allowed) == normalize_location(loc)
}

# Azure accepts both "swedencentral" and "Sweden Central".
normalize_location(s) := lower(replace(s, " ", ""))
