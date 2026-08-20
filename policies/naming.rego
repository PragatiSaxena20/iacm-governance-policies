package iacm.governance

name_pattern := "^(dev|qa|stage|prod)-[a-z0-9]+-[a-z0-9-]+-[0-9]{2}$"

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
	name := object.get(tags, "Name", "")

	name == ""

	msg := sprintf(
		"NAMING VIOLATION: Resource %s does not have a Name tag. Expected format: {environment}-{application}-{resource-type}-{number}, for example dev-payment-ec2-01.",
		[resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type in taggable_resource_types

	after := resource.change.after
	after != null

	tags := object.get(after, "tags", {})
	name := object.get(tags, "Name", "")

	name != ""
	not regex.match(name_pattern, name)

	msg := sprintf(
		"NAMING VIOLATION: Resource %s has invalid Name '%s'. Expected format: {environment}-{application}-{resource-type}-{number}, for example dev-payment-ec2-01.",
		[resource.address, name],
	)
}
