# Rule `tags`: every resource that can carry tags has all cloud.required_tags.
# Fail closed: tags that are only known after apply cannot be checked and are denied.
package main

import rego.v1

deny contains msg if {
	some rc in planned_resources
	known_tags(rc)
	missing := [t | some t in data.cloud.required_tags; not has_tag(rc, t); not unknown_tag(rc, t)]
	count(missing) > 0
	msg := denial(
		"tags",
		rc.address,
		sprintf("missing required tags %v.", [missing]),
		sprintf("set `tags = local.tags` on this resource; local.tags must contain %v with non-empty values.", [data.cloud.required_tags]),
	)
}

deny contains msg if {
	some rc in planned_resources
	after_unknown(rc, "tags")
	msg := denial(
		"tags",
		rc.address,
		"the tags are only known after apply, so the required tags cannot be checked.",
		"build `tags` only from values known at plan time (variables, locals, data sources), e.g. `tags = local.tags`.",
	)
}

deny contains msg if {
	some rc in planned_resources
	not after_unknown(rc, "tags")
	unknown := [t | some t in object.keys(unknown_tag_keys(rc)); unknown_tag(rc, t)]
	count(unknown) > 0
	msg := denial(
		"tags",
		rc.address,
		sprintf("the values of tags %v are only known after apply, so they cannot be checked.", [sort(unknown)]),
		"set these tags from values known at plan time (variables, locals, data sources).",
	)
}

# A resource supports tags when its schema exposes a `tags` attribute.
known_tags(rc) if {
	"tags" in object.keys(object.get(rc.change, "after", {}))
	not after_unknown(rc, "tags")
}

known_tags(rc) if {
	not "tags" in object.keys(object.get(rc.change, "after", {}))
	count(unknown_tag_keys(rc)) > 0
}

has_tag(rc, t) if {
	tags := after_attr(rc, "tags")
	is_object(tags)
	value := tags[t]
	is_string(value)
	value != ""
}

unknown_tag(rc, t) if unknown_tag_keys(rc)[t] == true

unknown_tag_keys(rc) := keys if {
	keys := object.get(object.get(rc.change, "after_unknown", {}), "tags", {})
	is_object(keys)
} else := {}
