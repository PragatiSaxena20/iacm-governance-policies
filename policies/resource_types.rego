package iacm.governance

allowed_resource_types := {
	"aws_instance",
	"aws_s3_bucket",
	"aws_s3_bucket_public_access_block",
	"aws_s3_bucket_server_side_encryption_configuration",
	"aws_security_group",
}

allowed_instance_types := {
	"t3.micro",
	"t3.small",
	"t3.medium",
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"

	not allowed_resource_types[resource.type]

	msg := sprintf(
		"RESOURCE TYPE VIOLATION: Resource type '%s' at %s is not approved.",
		[resource.type, resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_instance"

	instance_type := resource.change.after.instance_type

	not allowed_instance_types[instance_type]

	msg := sprintf(
		"INSTANCE TYPE VIOLATION: EC2 instance %s uses '%s'. Allowed instance types are: t3.micro, t3.small, t3.medium.",
		[resource.address, instance_type],
	)
}
