package iacm.governance_test

import data.iacm.governance

test_invalid_name_is_denied {
	input := {
		"resource_changes": [
			{
				"address": "aws_instance.web",
				"mode": "managed",
				"type": "aws_instance",
				"name": "web",
				"change": {
					"after": {
						"tags": {
							"Name": "bad_server",
							"environment": "dev",
							"owner": "platform-team",
							"cost-center": "CC1001",
							"managed-by": "harness"
						}
					}
				}
			}
		]
	}

	count(governance.deny) > 0 with input as input
}

test_valid_name_is_allowed {
	input := {
		"resource_changes": [
			{
				"address": "aws_instance.web",
				"mode": "managed",
				"type": "aws_instance",
				"name": "web",
				"change": {
					"after": {
						"tags": {
							"Name": "dev-payment-ec2-01",
							"environment": "dev",
							"owner": "platform-team",
							"cost-center": "CC1001",
							"managed-by": "harness"
						}
					}
				}
			}
		]
	}

	count(governance.deny) == 0 with input as input
}
