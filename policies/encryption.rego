package iacm.governance

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_s3_bucket"

	after := resource.change.after
	after != null

	not s3_encryption_exists(resource.name)

	msg := sprintf(
		"ENCRYPTION VIOLATION: S3 bucket %s must have server-side encryption configured.",
		[resource.address],
	)
}

s3_encryption_exists(bucket_name) {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_s3_bucket_server_side_encryption_configuration"
	resource.name == bucket_name
}
