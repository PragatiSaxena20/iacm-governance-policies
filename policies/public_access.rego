package iacm.governance

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_s3_bucket_public_access_block"

	after := resource.change.after

	after.block_public_acls != true

	msg := sprintf(
		"PUBLIC ACCESS VIOLATION: S3 bucket %s must have block_public_acls enabled.",
		[resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_s3_bucket_public_access_block"

	after := resource.change.after

	after.block_public_policy != true

	msg := sprintf(
		"PUBLIC ACCESS VIOLATION: S3 bucket %s must have block_public_policy enabled.",
		[resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_s3_bucket_public_access_block"

	after := resource.change.after

	after.ignore_public_acls != true

	msg := sprintf(
		"PUBLIC ACCESS VIOLATION: S3 bucket %s must have ignore_public_acls enabled.",
		[resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_s3_bucket_public_access_block"

	after := resource.change.after

	after.restrict_public_buckets != true

	msg := sprintf(
		"PUBLIC ACCESS VIOLATION: S3 bucket %s must have restrict_public_buckets enabled.",
		[resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_security_group"

	after := resource.change.after

	rule := after.ingress[_]

	rule.cidr_blocks[_] == "0.0.0.0/0"

	rule.from_port <= 22
	rule.to_port >= 22

	msg := sprintf(
		"PUBLIC ACCESS VIOLATION: Security group %s allows unrestricted SSH access from 0.0.0.0/0.",
		[resource.address],
	)
}

deny[msg] {
	resource := input.resource_changes[_]

	resource.mode == "managed"
	resource.type == "aws_security_group"

	after := resource.change.after

	rule := after.ingress[_]

	rule.cidr_blocks[_] == "0.0.0.0/0"

	rule.from_port <= 3389
	rule.to_port >= 3389

	msg := sprintf(
		"PUBLIC ACCESS VIOLATION: Security group %s allows unrestricted RDP access from 0.0.0.0/0.",
		[resource.address],
	)
}
