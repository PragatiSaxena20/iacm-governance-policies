package iacm.governance_test

import data.iacm.governance

test_missing_required_tag_is_denied {
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
							"managed-by": "harness"
						}
					}
				}
			}
		]
	}

	count(governance.deny) > 0 with input as input
}

test_all_required_tags_are_allowed {
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
