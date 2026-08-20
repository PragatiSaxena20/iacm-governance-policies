package iacm.governance_test

import data.iacm.governance

test_s3_without_encryption_is_denied {
	input := {
		"resource_changes": [
			{
				"address": "aws_s3_bucket.app",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "app",
				"change": {
					"after": {
						"bucket": "dev-payment-s3-01"
					}
				}
			}
		]
	}

	count(governance.deny) > 0 with input as input
}

test_s3_with_encryption_is_allowed {
	input := {
		"resource_changes": [
			{
				"address": "aws_s3_bucket.app",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"name": "app",
				"change": {
					"after": {
						"bucket": "dev-payment-s3-01"
					}
				}
			},
			{
				"address": "aws_s3_bucket_server_side_encryption_configuration.app",
				"mode": "managed",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"name": "app",
				"change": {
					"after": {
						"bucket": "dev-payment-s3-01"
					}
				}
			}
		]
	}

	count(governance.deny) == 0 with input as input
}
