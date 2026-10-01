# Rule `resource_types`: only types listed in cloud.allowed_resource_types.
package main

import rego.v1

deny contains msg if {
	some rc in planned_resources
	not rc.type in {t | some t in data.cloud.allowed_resource_types}
	msg := denial(
		"resource_types",
		rc.address,
		sprintf("resource type %q is not allowed on this platform.", [rc.type]),
		sprintf("remove this resource or use one of the allowed types %v; only the platform team can extend cloud.allowed_resource_types.", [data.cloud.allowed_resource_types]),
	)
}
