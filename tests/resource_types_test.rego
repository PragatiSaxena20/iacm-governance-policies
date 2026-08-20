package iacm.governance_test

import data.iacm.governance

test_unapproved_resource_type_is_denied {
	input := {
		"resource_changes": [
			{
				"address": "aws_db_instance.database",
				"mode": "managed",
				"type": "aws_db_instance",
				"name": "database",
				"change": {
					"after": {}
				}
			}
		]
	}

	count(governance.deny) > 0 with input as input
}

test_unapproved_ec2_type_is_denied {
	input := {
		"resource_changes": [
			{
				"address": "aws_instance.web",
				"mode": "managed",
				"type": "aws_instance",
				"name": "web",
				"change": {
					"after": {
						"instance_type": "m5.4xlarge"
					}
				}
			}
		]
	}

	count(governance.deny) > 0 with input as input
}

test_approved_ec2_type_is_allowed {
	input := {
		"resource_changes": [
			{
				"address": "aws_instance.web",
				"mode": "managed",
				"type": "aws_instance",
				"name": "web",
				"change": {
					"after": {
						"instance_type": "t3.micro"
					}
				}
			}
		]
	}

	count(governance.deny) == 0 with input as input
}
