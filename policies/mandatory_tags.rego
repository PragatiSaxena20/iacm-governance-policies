package iacm.governance

required_tags := {
	"environment",
	"owner",
	"cost-center",
	"managed-by",
}

taggable_resource_types := {
	"aws_instance",
	"aws_s3_bucket",
	"aws_security_group",
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type in taggable_resource_types

	after := resource.change.after
	after != null

	tags := object.get(after, "tags", {})

	required_tag := required_tags[_]

	not tags[required_tag]

	msg := sprintf(
		"MANDATORY TAG VIOLATION: Resource %s is missing required tag '%s'. Required tags are: environment, owner, cost-center, managed-by.",
		[resource.address, required_tag],
	)
}
