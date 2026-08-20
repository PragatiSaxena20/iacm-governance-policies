package iacm.governance_test

import data.iacm.governance

test_public_ssh_is_denied {
	input := {
		"resource_changes": [
			{
				"address": "aws_security_group.web",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "web",
				"change": {
					"after": {
						"ingress": [
							{
								"from_port": 22,
								"to_port": 22,
								"protocol": "tcp",
								"cidr_blocks": [
									"0.0.0.0/0"
								]
							}
						]
					}
				}
			}
		]
	}

	count(governance.deny) > 0 with input as input
}

test_private_ssh_is_allowed {
	input := {
		"resource_changes": [
			{
				"address": "aws_security_group.web",
				"mode": "managed",
				"type": "aws_security_group",
				"name": "web",
				"change": {
					"after": {
						"ingress": [
							{
								"from_port": 22,
								"to_port": 22,
								"protocol": "tcp",
								"cidr_blocks": [
									"10.0.0.0/8"
								]
							}
						]
					}
				}
			}
		]
	}

	count(governance.deny) == 0 with input as input
}
