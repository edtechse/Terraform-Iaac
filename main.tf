terraform {
    required_providers {
        aws = {
            source = "hashicorp/aws"
            version = "~> 3.0"
        }
    }
}

provider "aws" {
    region = "ap-southeast-1"
}

resource "aws_iam_user" "IAMUser" {
    path = "/"
    name = "Cloudformation"
    tags {}
}

resource "aws_iam_user" "IAMUser2" {
    path = "/"
    name = "EdTech-SDK"
    tags {}
}

resource "aws_iam_role" "IAMRole" {
    path = "/"
    name = "DAXServiceRoleForDynamoDBAccess"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"dax.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole2" {
    path = "/service-role/"
    name = "blog-es-function-role-5wzhtcj4"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole3" {
    path = "/service-role/"
    name = "DAXtoDynamoDB"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"dax.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole4" {
    path = "/"
    name = "AWSUsageReport-AWSUsageLambdaFunctionIamRole-18L5NEXXV9C6Z"
    assume_role_policy = "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole5" {
    path = "/"
    name = "ecsTaskExecutionRole"
    assume_role_policy = "{\"Version\":\"2008-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ecs-tasks.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole6" {
    path = "/"
    name = "EC2InstanceRole"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole7" {
    path = "/"
    name = "masters.edtech.k8s.local"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ec2.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {
        Name = "masters.edtech.k8s.local"
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
}

resource "aws_iam_role" "IAMRole8" {
    path = "/"
    name = "rds-monitoring-role"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"monitoring.rds.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole9" {
    path = "/service-role/"
    name = "qna-es-function-role-93mbre9o"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole10" {
    path = "/service-role/"
    name = "edTechuserpool-SMS-Role"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cognito-idp.amazonaws.com\"},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"c1c7e8a8-fc13-4b6e-bfd9-c284f731152b\"}}}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_role" "IAMRole11" {
    path = "/"
    name = "nodes.edtech.k8s.local"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"cloudwatch.amazonaws.com\",\"dax.amazonaws.com\",\"sqs.amazonaws.com\",\"ec2.amazonaws.com\"]},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {
        Name = "nodes.edtech.k8s.local"
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
}

resource "aws_iam_role" "IAMRole12" {
    path = "/"
    name = "MyDAXRoleForDynamoDBAccess"
    assume_role_policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"dax.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}"
    max_session_duration = 3600
    tags {}
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole" {
    aws_service_name = "guardduty.amazonaws.com"
    description = "A service-linked role required for Amazon GuardDuty to access your resources. "
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole2" {
    aws_service_name = "ops.apigateway.amazonaws.com"
    description = "The Service Linked Role is used by Amazon API Gateway."
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole3" {
    aws_service_name = "opensearchservice.amazonaws.com"
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole4" {
    aws_service_name = "autoscaling.amazonaws.com"
    description = "Default Service-Linked Role enables access to AWS Services and Resources used or managed by Auto Scaling"
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole5" {
    aws_service_name = "dynamodb.application-autoscaling.amazonaws.com"
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole6" {
    aws_service_name = "config.amazonaws.com"
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole7" {
    aws_service_name = "ecs.amazonaws.com"
    description = "Role to enable Amazon ECS to manage your cluster."
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole8" {
    aws_service_name = "dax.amazonaws.com"
    description = "This policy allows DAX to manage AWS resources on your behalf as necessary for managing your cache."
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole9" {
    aws_service_name = "elasticloadbalancing.amazonaws.com"
    description = "Allows ELB to call AWS services on your behalf."
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole10" {
    aws_service_name = "rds.amazonaws.com"
    description = "Allows Amazon RDS to manage AWS resources on your behalf"
}

resource "aws_iam_service_linked_role" "IAMServiceLinkedRole11" {
    aws_service_name = "securityhub.amazonaws.com"
    description = "A service-linked role required for AWS Security Hub to access your resources."
}

resource "aws_iam_policy" "IAMManagedPolicy" {
    name = "Cloudwatch-accesslogs"
    path = "/"
    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
    ],
      "Resource": [
        "arn:aws:logs:*:*:*"
    ]
  }
 ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy2" {
    name = "DAXReadAccess-DAXtoDynamoDB"
    path = "/service-role/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchGetItem",
                "dynamodb:GetItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:DescribeLimits",
                "dynamodb:DescribeTimeToLive",
                "dynamodb:DescribeTable",
                "dynamodb:ListTables"
            ],
            "Resource": [
                "arn:aws:dynamodb:ap-southeast-1:162387011843:table/*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy3" {
    name = "AWSLambdaBasicExecutionRole-61243026-0da6-4381-a324-73b8b77c9a2e"
    path = "/service-role/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:ap-southeast-1:162387011843:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:ap-southeast-1:162387011843:log-group:/aws/lambda/qna-es-function:*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy4" {
    name = "Cognito-1633423734632"
    path = "/service-role/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sns:publish"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy5" {
    name = "DAXServicePolicyForDynamoDBAccess"
    path = "/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dynamodb:DescribeTable",
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchGetItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:ConditionCheckItem"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:dynamodb:ap-southeast-1:162387011843:*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy6" {
    name = "MyDAXUserPolicy"
    path = "/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dax:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        },
        {
            "Action": [
                "dynamodb:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy7" {
    name = "MyDAXPolicyForDynamoDBAccess"
    path = "/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dynamodb:DescribeTable",
                "dynamodb:PutItem",
                "dynamodb:GetItem",
                "dynamodb:UpdateItem",
                "dynamodb:DeleteItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchGetItem",
                "dynamodb:BatchWriteItem",
                "dynamodb:ConditionCheckItem"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:dynamodb:ap-southeast-1:162387011843:*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_policy" "IAMManagedPolicy8" {
    name = "AWSLambdaBasicExecutionRole-63cdf7e4-d92c-4a49-ba75-211919b2a38b"
    path = "/service-role/"
    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:ap-southeast-1:162387011843:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:ap-southeast-1:162387011843:log-group:/aws/lambda/blog-es-function:*"
            ]
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "IAMPolicy" {
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Action\":[\"ec2:DescribeInstances\",\"ec2:DescribeAddresses\",\"ec2:DescribeRegions\",\"ec2:DescribeVolumes\",\"pricing:GetProducts\"],\"Resource\":\"*\",\"Effect\":\"Allow\"},{\"Action\":[\"ses:SendRawEmail\",\"ses:ListIdentities\",\"ses:ListVerifiedEmailAddresses\",\"ses:VerifyEmailAddress\"],\"Resource\":\"*\",\"Effect\":\"Allow\"},{\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],\"Resource\":\"*\",\"Effect\":\"Allow\"}]}"
    role = "${aws_iam_role.IAMRole4.name}"
}

resource "aws_iam_role_policy" "IAMPolicy2" {
    policy = <<EOF
{
  "Statement": [
    {
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeRegions"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": "autoscaling:DescribeAutoScalingInstances",
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/addons/*",
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/cluster.spec",
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/config",
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/instancegroup/*",
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/pki/issued/*",
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/pki/ssh/*",
        "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/secrets/dockerconfig"
      ]
    },
    {
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::edtech.k8s.local-state-store"
      ]
    },
    {
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    }
  ],
  "Version": "2012-10-17"
}
EOF
    role = "${aws_iam_role.IAMRole11.name}"
}

resource "aws_iam_role_policy" "IAMPolicy3" {
    policy = <<EOF
{
  "Statement": [
    {
      "Action": [
        "ec2:DescribeAccountAttributes",
        "ec2:DescribeInstances",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeRegions",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "ec2:CreateSecurityGroup",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DescribeVolumesModifications",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyVolume"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CreateRoute",
        "ec2:DeleteRoute",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteVolume",
        "ec2:DetachVolume",
        "ec2:RevokeSecurityGroupIngress"
      ],
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/KubernetesCluster": "edtech.k8s.local"
        }
      },
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": "autoscaling:CompleteLifecycleAction",
      "Condition": {
        "StringEquals": {
          "autoscaling:ResourceTag/KubernetesCluster": "edtech.k8s.local"
        }
      },
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": "autoscaling:DescribeLifecycleHooks",
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": "autoscaling:DescribeAutoScalingInstances",
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:DescribeLaunchConfigurations",
        "autoscaling:DescribeTags",
        "ec2:DescribeLaunchTemplateVersions"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "autoscaling:SetDesiredCapacity",
        "autoscaling:TerminateInstanceInAutoScalingGroup",
        "autoscaling:UpdateAutoScalingGroup"
      ],
      "Condition": {
        "StringEquals": {
          "autoscaling:ResourceTag/KubernetesCluster": "edtech.k8s.local"
        }
      },
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "autoscaling:CompleteLifecycleAction",
        "autoscaling:DescribeAutoScalingInstances"
      ],
      "Condition": {
        "StringEquals": {
          "autoscaling:ResourceTag/KubernetesCluster": "edtech.k8s.local"
        }
      },
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "elasticloadbalancing:AddTags",
        "elasticloadbalancing:AttachLoadBalancerToSubnets",
        "elasticloadbalancing:ApplySecurityGroupsToLoadBalancer",
        "elasticloadbalancing:CreateLoadBalancer",
        "elasticloadbalancing:CreateLoadBalancerPolicy",
        "elasticloadbalancing:CreateLoadBalancerListeners",
        "elasticloadbalancing:ConfigureHealthCheck",
        "elasticloadbalancing:DeleteLoadBalancer",
        "elasticloadbalancing:DeleteLoadBalancerListeners",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DetachLoadBalancerFromSubnets",
        "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
        "elasticloadbalancing:ModifyLoadBalancerAttributes",
        "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
        "elasticloadbalancing:SetLoadBalancerPoliciesForBackendServer"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "ec2:DescribeVpcs",
        "elasticloadbalancing:AddTags",
        "elasticloadbalancing:CreateListener",
        "elasticloadbalancing:CreateTargetGroup",
        "elasticloadbalancing:DeleteListener",
        "elasticloadbalancing:DeleteTargetGroup",
        "elasticloadbalancing:DeregisterTargets",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeLoadBalancerPolicies",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:ModifyListener",
        "elasticloadbalancing:ModifyTargetGroup",
        "elasticloadbalancing:RegisterTargets",
        "elasticloadbalancing:SetLoadBalancerPoliciesOfListener"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "iam:ListServerCertificates",
        "iam:GetServerCertificate"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    },
    {
      "Action": [
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/*"
    },
    {
      "Action": [
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/backups/etcd/main/*"
    },
    {
      "Action": [
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::edtech.k8s.local-state-store/edtech.k8s.local/backups/etcd/events/*"
    },
    {
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:ListBucket",
        "s3:ListBucketVersions"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::edtech.k8s.local-state-store"
      ]
    },
    {
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:GetRepositoryPolicy",
        "ecr:DescribeRepositories",
        "ecr:ListImages",
        "ecr:BatchGetImage"
      ],
      "Effect": "Allow",
      "Resource": [
        "*"
      ]
    }
  ],
  "Version": "2012-10-17"
}
EOF
    role = "${aws_iam_role.IAMRole7.name}"
}

resource "aws_iam_instance_profile" "IAMInstanceProfile" {
    path = "/"
    name = "${aws_iam_role.IAMRole6.name}"
    roles = [
        "${aws_iam_role.IAMRole6.name}"
    ]
}

resource "aws_iam_instance_profile" "IAMInstanceProfile2" {
    path = "/"
    name = "${aws_iam_role.IAMRole7.name}"
    roles = [
        "${aws_iam_role.IAMRole7.name}"
    ]
}

resource "aws_iam_instance_profile" "IAMInstanceProfile3" {
    path = "/"
    name = "${aws_iam_role.IAMRole11.name}"
    roles = [
        "${aws_iam_role.IAMRole11.name}"
    ]
}

resource "aws_iam_access_key" "IAMAccessKey" {
    status = "Active"
    user = "Cloudformation"
}

resource "aws_iam_access_key" "IAMAccessKey2" {
    status = "Active"
    user = "EdTech-SDK"
}

resource "aws_vpc" "EC2VPC" {
    cidr_block = "172.31.0.0/16"
    enable_dns_support = true
    enable_dns_hostnames = true
    instance_tenancy = "default"
    tags {}
}

resource "aws_vpc" "EC2VPC2" {
    cidr_block = "172.20.0.0/16"
    enable_dns_support = true
    enable_dns_hostnames = true
    instance_tenancy = "default"
    tags {
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
        Name = "edtech.k8s.local"
    }
}

resource "aws_subnet" "EC2Subnet" {
    availability_zone = "ap-southeast-1b"
    cidr_block = "172.31.32.0/20"
    vpc_id = "${aws_vpc.EC2VPC.id}"
    map_public_ip_on_launch = true
}

resource "aws_subnet" "EC2Subnet2" {
    availability_zone = "ap-southeast-1a"
    cidr_block = "172.20.32.0/19"
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    map_public_ip_on_launch = false
}

resource "aws_subnet" "EC2Subnet3" {
    availability_zone = "ap-southeast-1a"
    cidr_block = "172.31.16.0/20"
    vpc_id = "${aws_vpc.EC2VPC.id}"
    map_public_ip_on_launch = true
}

resource "aws_subnet" "EC2Subnet4" {
    availability_zone = "ap-southeast-1c"
    cidr_block = "172.31.0.0/20"
    vpc_id = "${aws_vpc.EC2VPC.id}"
    map_public_ip_on_launch = true
}

resource "aws_subnet" "EC2Subnet5" {
    availability_zone = "ap-southeast-1b"
    cidr_block = "172.20.64.0/19"
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    map_public_ip_on_launch = false
}

resource "aws_internet_gateway" "EC2InternetGateway" {
    tags {
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        Name = "edtech.k8s.local"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
}

resource "aws_internet_gateway" "EC2InternetGateway2" {
    tags {}
    vpc_id = "${aws_vpc.EC2VPC.id}"
}

resource "aws_vpc_dhcp_options" "EC2DHCPOptions" {
    domain_name = "ap-southeast-1.compute.internal"
    tags {
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        Name = "edtech.k8s.local"
        KubernetesCluster = "edtech.k8s.local"
    }
}

resource "aws_vpc_dhcp_options" "EC2DHCPOptions2" {
    domain_name = "ap-southeast-1.compute.internal"
    tags {}
}

resource "aws_vpc_dhcp_options_association" "EC2VPCDHCPOptionsAssociation" {
    dhcp_options_id = "dopt-3a78b05c"
    vpc_id = "${aws_vpc.EC2VPC.id}"
}

resource "aws_vpc_dhcp_options_association" "EC2VPCDHCPOptionsAssociation2" {
    dhcp_options_id = "dopt-010614e904fd6476d"
    vpc_id = "${aws_vpc.EC2VPC2.id}"
}

resource "aws_network_acl" "EC2NetworkAcl" {
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    tags {}
}

resource "aws_network_acl" "EC2NetworkAcl2" {
    vpc_id = "${aws_vpc.EC2VPC.id}"
    tags {}
}

resource "aws_network_acl_rule" "EC2NetworkAclEntry" {
    cidr_block = "0.0.0.0/0"
    egress = true
    network_acl_id = "acl-06ab93175235a08c1"
    protocol = -1
    rule_action = "allow"
    rule_number = 100
}

resource "aws_network_acl_rule" "EC2NetworkAclEntry2" {
    cidr_block = "0.0.0.0/0"
    egress = false
    network_acl_id = "acl-06ab93175235a08c1"
    protocol = -1
    rule_action = "allow"
    rule_number = 100
}

resource "aws_network_acl_rule" "EC2NetworkAclEntry3" {
    cidr_block = "0.0.0.0/0"
    egress = true
    network_acl_id = "acl-77106a11"
    protocol = -1
    rule_action = "allow"
    rule_number = 100
}

resource "aws_network_acl_rule" "EC2NetworkAclEntry4" {
    cidr_block = "0.0.0.0/0"
    egress = false
    network_acl_id = "acl-77106a11"
    protocol = -1
    rule_action = "allow"
    rule_number = 100
}

resource "aws_route_table" "EC2RouteTable" {
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    tags {}
}

resource "aws_route_table" "EC2RouteTable2" {
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    tags {
        Name = "edtech.k8s.local"
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/kops/role = "public"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
}

resource "aws_route_table" "EC2RouteTable3" {
    vpc_id = "${aws_vpc.EC2VPC.id}"
    tags {}
}

resource "aws_route" "EC2Route" {
    destination_cidr_block = "100.96.0.0/24"
    instance_id = "i-0a39249880c3e61fe"
    network_interface_id = "eni-011ff5a0d87b1c686"
    route_table_id = "rtb-04a9bcf95284bf30a"
}

resource "aws_route" "EC2Route2" {
    destination_cidr_block = "100.96.1.0/24"
    instance_id = "i-0adb94f14aebcb25e"
    network_interface_id = "eni-023f648148879cd12"
    route_table_id = "rtb-04a9bcf95284bf30a"
}

resource "aws_route" "EC2Route3" {
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = "igw-0116e72f1b0477491"
    route_table_id = "rtb-04a9bcf95284bf30a"
}

resource "aws_route" "EC2Route4" {
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = "igw-adbb4bca"
    route_table_id = "rtb-3ebf9a58"
}

resource "aws_route_table_association" "EC2SubnetRouteTableAssociation" {
    route_table_id = "rtb-04a9bcf95284bf30a"
    subnet_id = "subnet-073aadc3871ef404e"
}

resource "aws_route_table_association" "EC2SubnetRouteTableAssociation2" {
    route_table_id = "rtb-04a9bcf95284bf30a"
    subnet_id = "subnet-052966279351b9b08"
}

resource "aws_instance" "EC2Instance" {
    ami = "ami-082105f875acab993"
    instance_type = "t3.large"
    key_name = "edtech-key"
    availability_zone = "ap-southeast-1a"
    tenancy = "default"
    subnet_id = "subnet-fb80059d"
    ebs_optimized = true
    vpc_security_group_ids = [
        "${aws_security_group.EC2SecurityGroup.id}"
    ]
    source_dest_check = true
    root_block_device {
        volume_size = 50
        volume_type = "gp2"
        delete_on_termination = true
    }
    iam_instance_profile = "${aws_iam_role.IAMRole6.name}"
    tags {
        Name = "edtech-build-server"
    }
}

resource "aws_instance" "EC2Instance2" {
    ami = "ami-082105f875acab993"
    instance_type = "t2.micro"
    key_name = "deployment-ec2-blogs"
    availability_zone = "ap-southeast-1a"
    tenancy = "default"
    subnet_id = "subnet-fb80059d"
    ebs_optimized = false
    vpc_security_group_ids = [
        "${aws_security_group.EC2SecurityGroup6.id}"
    ]
    source_dest_check = true
    root_block_device {
        volume_size = 8
        volume_type = "gp2"
        delete_on_termination = true
    }
    iam_instance_profile = "${aws_iam_role.IAMRole6.name}"
    tags {
        Name = "deployment-ec2"
    }
}

resource "aws_instance" "EC2Instance3" {
    ami = "ami-082105f875acab993"
    instance_type = "t2.micro"
    key_name = "DAXKeypair"
    availability_zone = "ap-southeast-1a"
    tenancy = "default"
    subnet_id = "subnet-fb80059d"
    ebs_optimized = false
    vpc_security_group_ids = [
        "${aws_security_group.EC2SecurityGroup15.id}"
    ]
    source_dest_check = true
    root_block_device {
        volume_size = 8
        volume_type = "gp2"
        delete_on_termination = true
    }
    tags {
        Name = "dax-connector"
    }
}

resource "aws_instance" "EC2Instance4" {
    ami = "ami-0c07cd0ceb5369def"
    instance_type = "t3.medium"
    key_name = "kubernetes.edtech.k8s.local-61:ea:d4:fe:46:60:58:76:57:c3:2f:2d:7f:aa:30:2a"
    availability_zone = "ap-southeast-1b"
    tenancy = "default"
    subnet_id = "subnet-052966279351b9b08"
    ebs_optimized = false
    vpc_security_group_ids = [
        "${aws_security_group.EC2SecurityGroup3.id}"
    ]
    source_dest_check = false
    ebs_block_device {
        device_name = "/dev/xvdbb"
        encrypted = false
        volume_size = 2
        snapshot_id = ""
        volume_type = "gp2"
        delete_on_termination = false
    }
    ebs_block_device {
        device_name = "/dev/xvdbl"
        encrypted = false
        volume_size = 8
        snapshot_id = ""
        volume_type = "gp2"
        delete_on_termination = false
    }
    root_block_device {
        volume_size = 128
        volume_type = "gp3"
        delete_on_termination = true
    }
    user_data = "IyEvYmluL2Jhc2gKc2V0IC1vIGVycmV4aXQKc2V0IC1vIG5vdW5zZXQKc2V0IC1vIHBpcGVmYWlsCgpOT0RFVVBfVVJMX0FNRDY0PWh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9ub2RldXAsaHR0cHM6Ly9naXRodWIuY29tL2t1YmVybmV0ZXMva29wcy9yZWxlYXNlcy9kb3dubG9hZC92MS4yMS4xL25vZGV1cC1saW51eC1hbWQ2NApOT0RFVVBfSEFTSF9BTUQ2ND1kYjM0ZDM4OTRlMGJhNmY5YTMxN2MzMGI1ZGUxNWRmYjQzZTFhMTkxMjhlODYxNTcyNGMwODJjNGI5ZWZkZGY0Ck5PREVVUF9VUkxfQVJNNjQ9aHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L25vZGV1cCxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvbm9kZXVwLWxpbnV4LWFybTY0Ck5PREVVUF9IQVNIX0FSTTY0PWVlZGQxYzM0MmMwMzkwMGIwOWQ3MmNjMzIzYTZkZWRiMzc4NDI3YjBmMmQ2ZGM0MzY3MDQ4ZDM2OTgzNmM3OGYKCmV4cG9ydCBBV1NfUkVHSU9OPWFwLXNvdXRoZWFzdC0xCgoKCgpzeXNjdGwgLXcgbmV0LmlwdjQudGNwX3JtZW09JzQwOTYgMTI1ODI5MTIgMTY3NzcyMTYnIHx8IHRydWUKCgpmdW5jdGlvbiBlbnN1cmUtaW5zdGFsbC1kaXIoKSB7CiAgSU5TVEFMTF9ESVI9Ii9vcHQva29wcyIKICAjIE9uIENvbnRhaW5lck9TLCB3ZSBpbnN0YWxsIHVuZGVyIC92YXIvbGliL3Rvb2xib3g7IC9vcHQgaXMgcm8gYW5kIG5vZXhlYwogIGlmIFtbIC1kIC92YXIvbGliL3Rvb2xib3ggXV07IHRoZW4KICAgIElOU1RBTExfRElSPSIvdmFyL2xpYi90b29sYm94L2tvcHMiCiAgZmkKICBta2RpciAtcCAke0lOU1RBTExfRElSfS9iaW4KICBta2RpciAtcCAke0lOU1RBTExfRElSfS9jb25mCiAgY2QgJHtJTlNUQUxMX0RJUn0KfQoKIyBSZXRyeSBhIGRvd25sb2FkIHVudGlsIHdlIGdldCBpdC4gYXJnczogbmFtZSwgc2hhLCB1cmwxLCB1cmwyLi4uCmRvd25sb2FkLW9yLWJ1c3QoKSB7CiAgbG9jYWwgLXIgZmlsZT0iJDEiCiAgbG9jYWwgLXIgaGFzaD0iJDIiCiAgc2hpZnQgMgoKICB1cmxzPSggJCogKQogIHdoaWxlIHRydWU7IGRvCiAgICBmb3IgdXJsIGluICIke3VybHNbQF19IjsgZG8KICAgICAgY29tbWFuZHM9KAogICAgICAgICJjdXJsIC1mIC0taXB2NCAtLWNvbXByZXNzZWQgLUxvICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dCAyMCAtLXJldHJ5IDYgLS1yZXRyeS1kZWxheSAxMCIKICAgICAgICAid2dldCAtLWluZXQ0LW9ubHkgLS1jb21wcmVzc2lvbj1hdXRvIC1PICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dD0yMCAtLXRyaWVzPTYgLS13YWl0PTEwIgogICAgICAgICJjdXJsIC1mIC0taXB2NCAtTG8gIiR7ZmlsZX0iIC0tY29ubmVjdC10aW1lb3V0IDIwIC0tcmV0cnkgNiAtLXJldHJ5LWRlbGF5IDEwIgogICAgICAgICJ3Z2V0IC0taW5ldDQtb25seSAtTyAiJHtmaWxlfSIgLS1jb25uZWN0LXRpbWVvdXQ9MjAgLS10cmllcz02IC0td2FpdD0xMCIKICAgICAgKQogICAgICBmb3IgY21kIGluICIke2NvbW1hbmRzW0BdfSI7IGRvCiAgICAgICAgZWNobyAiQXR0ZW1wdGluZyBkb3dubG9hZCB3aXRoOiAke2NtZH0ge3VybH0iCiAgICAgICAgaWYgISAoJHtjbWR9ICIke3VybH0iKTsgdGhlbgogICAgICAgICAgZWNobyAiPT0gRG93bmxvYWQgZmFpbGVkIHdpdGggJHtjbWR9ID09IgogICAgICAgICAgY29udGludWUKICAgICAgICBmaQogICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXSAmJiAhIHZhbGlkYXRlLWhhc2ggIiR7ZmlsZX0iICIke2hhc2h9IjsgdGhlbgogICAgICAgICAgZWNobyAiPT0gSGFzaCB2YWxpZGF0aW9uIG9mICR7dXJsfSBmYWlsZWQuIFJldHJ5aW5nLiA9PSIKICAgICAgICAgIHJtIC1mICIke2ZpbGV9IgogICAgICAgIGVsc2UKICAgICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXTsgdGhlbgogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSAoU0hBMSA9ICR7aGFzaH0pID09IgogICAgICAgICAgZWxzZQogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSA9PSIKICAgICAgICAgIGZpCiAgICAgICAgICByZXR1cm4KICAgICAgICBmaQogICAgICBkb25lCiAgICBkb25lCgogICAgZWNobyAiQWxsIGRvd25sb2FkcyBmYWlsZWQ7IHNsZWVwaW5nIGJlZm9yZSByZXRyeWluZyIKICAgIHNsZWVwIDYwCiAgZG9uZQp9Cgp2YWxpZGF0ZS1oYXNoKCkgewogIGxvY2FsIC1yIGZpbGU9IiQxIgogIGxvY2FsIC1yIGV4cGVjdGVkPSIkMiIKICBsb2NhbCBhY3R1YWwKCiAgYWN0dWFsPSQoc2hhMjU2c3VtICR7ZmlsZX0gfCBhd2sgJ3sgcHJpbnQgJDEgfScpIHx8IHRydWUKICBpZiBbWyAiJHthY3R1YWx9IiAhPSAiJHtleHBlY3RlZH0iIF1dOyB0aGVuCiAgICBlY2hvICI9PSAke2ZpbGV9IGNvcnJ1cHRlZCwgaGFzaCAke2FjdHVhbH0gZG9lc24ndCBtYXRjaCBleHBlY3RlZCAke2V4cGVjdGVkfSA9PSIKICAgIHJldHVybiAxCiAgZmkKfQoKZnVuY3Rpb24gc3BsaXQtY29tbWFzKCkgewogIGVjaG8gJDEgfCB0ciAiLCIgIlxuIgp9CgpmdW5jdGlvbiB0cnktZG93bmxvYWQtcmVsZWFzZSgpIHsKICBsb2NhbCAtciBub2RldXBfdXJscz0oICQoc3BsaXQtY29tbWFzICIke05PREVVUF9VUkx9IikgKQogIGlmIFtbIC1uICIke05PREVVUF9IQVNIOi19IiBdXTsgdGhlbgogICAgbG9jYWwgLXIgbm9kZXVwX2hhc2g9IiR7Tk9ERVVQX0hBU0h9IgogIGVsc2UKICAjIFRPRE86IFJlbW92ZT8KICAgIGVjaG8gIkRvd25sb2FkaW5nIHNoYTI1NiAobm90IGZvdW5kIGluIGVudikiCiAgICBkb3dubG9hZC1vci1idXN0IG5vZGV1cC5zaGEyNTYgIiIgIiR7bm9kZXVwX3VybHNbQF0vJS8uc2hhMjU2fSIKICAgIGxvY2FsIC1yIG5vZGV1cF9oYXNoPSQoY2F0IG5vZGV1cC5zaGEyNTYpCiAgZmkKCiAgZWNobyAiRG93bmxvYWRpbmcgbm9kZXVwICgke25vZGV1cF91cmxzW0BdfSkiCiAgZG93bmxvYWQtb3ItYnVzdCBub2RldXAgIiR7bm9kZXVwX2hhc2h9IiAiJHtub2RldXBfdXJsc1tAXX0iCgogIGNobW9kICt4IG5vZGV1cAp9CgpmdW5jdGlvbiBkb3dubG9hZC1yZWxlYXNlKCkgewogIGNhc2UgIiQodW5hbWUgLW0pIiBpbgogIHg4Nl82NCp8aT84Nl82NCp8YW1kNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FNRDY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FNRDY0fSIKICAgIDs7CiAgYWFyY2g2NCp8YXJtNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FSTTY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FSTTY0fSIKICAgIDs7CiAgKikKICAgIGVjaG8gIlVuc3VwcG9ydGVkIGhvc3QgYXJjaDogJCh1bmFtZSAtbSkiID4mMgogICAgZXhpdCAxCiAgICA7OwogIGVzYWMKCiAgIyBJbiBjYXNlIG9mIGZhaWx1cmUgY2hlY2tpbmcgaW50ZWdyaXR5IG9mIHJlbGVhc2UsIHJldHJ5LgogIGNkICR7SU5TVEFMTF9ESVJ9L2JpbgogIHVudGlsIHRyeS1kb3dubG9hZC1yZWxlYXNlOyBkbwogICAgc2xlZXAgMTUKICAgIGVjaG8gIkNvdWxkbid0IGRvd25sb2FkIHJlbGVhc2UuIFJldHJ5aW5nLi4uIgogIGRvbmUKCiAgZWNobyAiUnVubmluZyBub2RldXAiCiAgIyBXZSBjYW4ndCBydW4gaW4gdGhlIGZvcmVncm91bmQgYmVjYXVzZSBvZiBodHRwczovL2dpdGh1Yi5jb20vZG9ja2VyL2RvY2tlci9pc3N1ZXMvMjM3OTMKICAoIGNkICR7SU5TVEFMTF9ESVJ9L2JpbjsgLi9ub2RldXAgLS1pbnN0YWxsLXN5c3RlbWQtdW5pdCAtLWNvbmY9JHtJTlNUQUxMX0RJUn0vY29uZi9rdWJlX2Vudi55YW1sIC0tdj04ICApCn0KCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoKL2Jpbi9zeXN0ZW1kLW1hY2hpbmUtaWQtc2V0dXAgfHwgZWNobyAiZmFpbGVkIHRvIHNldCB1cCBlbnN1cmUgbWFjaGluZS1pZCBjb25maWd1cmVkIgoKZWNobyAiPT0gbm9kZXVwIG5vZGUgY29uZmlnIHN0YXJ0aW5nID09IgplbnN1cmUtaW5zdGFsbC1kaXIKCmNhdCA+IGNvbmYvY2x1c3Rlcl9zcGVjLnlhbWwgPDwgJ19fRU9GX0NMVVNURVJfU1BFQycKY2xvdWRDb25maWc6CiAgYXdzRUJTQ1NJRHJpdmVyOgogICAgZW5hYmxlZDogZmFsc2UKICBtYW5hZ2VTdG9yYWdlQ2xhc3NlczogdHJ1ZQpjb250YWluZXJSdW50aW1lOiBjb250YWluZXJkCmNvbnRhaW5lcmQ6CiAgY29uZmlnT3ZlcnJpZGU6IHwKICAgIHZlcnNpb24gPSAyCgogICAgW3BsdWdpbnNdCgogICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSJdCgogICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jbmldCiAgICAgICAgICBjb25mX3RlbXBsYXRlID0gIi9ldGMvY29udGFpbmVyZC9jb25maWctY25pLnRlbXBsYXRlIgoKICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZF0KCiAgICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZC5ydW50aW1lc10KCiAgICAgICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jb250YWluZXJkLnJ1bnRpbWVzLnJ1bmNdCiAgICAgICAgICAgICAgcnVudGltZV90eXBlID0gImlvLmNvbnRhaW5lcmQucnVuYy52MiIKCiAgICAgICAgICAgICAgW3BsdWdpbnMuImlvLmNvbnRhaW5lcmQuZ3JwYy52MS5jcmkiLmNvbnRhaW5lcmQucnVudGltZXMucnVuYy5vcHRpb25zXQogICAgICAgICAgICAgICAgU3lzdGVtZENncm91cCA9IHRydWUKICBsb2dMZXZlbDogaW5mbwogIHZlcnNpb246IDEuNC45CmRvY2tlcjoKICBza2lwSW5zdGFsbDogdHJ1ZQprdWJlUHJveHk6CiAgY2x1c3RlckNJRFI6IDEwMC45Ni4wLjAvMTEKICBjcHVSZXF1ZXN0OiAxMDBtCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAgaW1hZ2U6IGs4cy5nY3IuaW8va3ViZS1wcm94eTp2MS4yMS41CiAgbG9nTGV2ZWw6IDIKa3ViZWxldDoKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGNncm91cERyaXZlcjogc3lzdGVtZAogIGNncm91cFJvb3Q6IC8KICBjbG91ZFByb3ZpZGVyOiBhd3MKICBjbHVzdGVyRE5TOiAxMDAuNjQuMC4xMAogIGNsdXN0ZXJEb21haW46IGNsdXN0ZXIubG9jYWwKICBlbmFibGVEZWJ1Z2dpbmdIYW5kbGVyczogdHJ1ZQogIGV2aWN0aW9uSGFyZDogbWVtb3J5LmF2YWlsYWJsZTwxMDBNaSxub2RlZnMuYXZhaWxhYmxlPDEwJSxub2RlZnMuaW5vZGVzRnJlZTw1JSxpbWFnZWZzLmF2YWlsYWJsZTwxMCUsaW1hZ2Vmcy5pbm9kZXNGcmVlPDUlCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAga3ViZWNvbmZpZ1BhdGg6IC92YXIvbGliL2t1YmVsZXQva3ViZWNvbmZpZwogIGxvZ0xldmVsOiAyCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKCl9fRU9GX0NMVVNURVJfU1BFQwoKY2F0ID4gY29uZi9pZ19zcGVjLnlhbWwgPDwgJ19fRU9GX0lHX1NQRUMnCnt9CgpfX0VPRl9JR19TUEVDCgpjYXQgPiBjb25mL2t1YmVfZW52LnlhbWwgPDwgJ19fRU9GX0tVQkVfRU5WJwpBc3NldHM6CiAgYW1kNjQ6CiAgLSA2MDBmNzBmZTBlNjkxNTFiOWQ4YWM2NWVjMTk1YmNjODQwNjg3Zjg2YmEzOTdmY2UyN2JlMWZhYWUzNTM4YTZmQGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlbGV0CiAgLSAwNjBlZGU3NTU1MGM2M2JkYzg0ZTE0ZmNjNGM4YWIzMDE3ZjdmZmMwMzJmYzRjYWMzYmYyMGQyNzRmYWIxYmU0QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlY3RsCiAgLSA5Nzc4MjQ5MzJkNTY2N2M3YTM3YWE2YTNjYmJhNDAxMDBhNjg3M2U3YmQ5N2U4M2U4YmU4MzdlM2U3YWZkMGE4QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rOHMtYXJ0aWZhY3RzLWNuaS9yZWxlYXNlL3YwLjguNy9jbmktcGx1Z2lucy1saW51eC1hbWQ2NC12MC44LjcudGd6CiAgLSA5OTExNDc5Zjg2MDEyZDZlYWI3ZTBmNTMyZGE4ZjgwN2E4YjBmNTU1ZWUwOWVmODkzNjdkOGMzMTI0MzA3M2JiQGh0dHBzOi8vZ2l0aHViLmNvbS9jb250YWluZXJkL2NvbnRhaW5lcmQvcmVsZWFzZXMvZG93bmxvYWQvdjEuNC45L2NyaS1jb250YWluZXJkLWNuaS0xLjQuOS1saW51eC1hbWQ2NC50YXIuZ3oKICAtIGE0NzFmMDQ4ZGIyZjFlMzUyMzc5MTAwYWUwZDkyY2I0NDcxMWQ4OTY5MzQxZTI4NmNiYTI2Y2Y1ODFjM2MyZTJAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FtZDY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFtZDY0CiAgLSAyOWU1NGE4OTYxNzE5MTU1ZWQyODdjMWZiYTViMDUyNGM3YTI1ZmFjNDc0YWFjMDA5YTJlNGNiN2ViYzQxZGJlQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYW1kNjQKICBhcm02NDoKICAtIDc0NmE1MzU5NTZkYjU1ODA3ZWY3MTc3MmQyYTRhZmVjNWNjNDM4MjMzZGEyMzk1MjE2N2VjMGFlYzZmZTkzN2JAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVsZXQKICAtIGZjYThkZTdlNTViNTVjY2VhYjk5MDJhYWUwMzgzN2ZiMmYxZTcyYjk3YWEwOWIyYWM5NjI2YmRiZmQwNDY2ZTRAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVjdGwKICAtIGFlMTNkN2I1YzA1YmQxODBlYTliNWI2OGY0NGJkYWE3YmZiNDEwMzRhMmVmMWQ2OGZkOGUxMjU5Nzk3ZDY0MmZAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2s4cy1hcnRpZmFjdHMtY25pL3JlbGVhc2UvdjAuOC43L2NuaS1wbHVnaW5zLWxpbnV4LWFybTY0LXYwLjguNy50Z3oKICAtIDRlYjlkNWUyYWRmNzE4Y2Q3ZWU1OWY2OTUxNzE1ZjMxMTNjOWM0ZWU0OWM3NWM5ZWZiOTc0N2YyYzM0NTdiMmJAaHR0cHM6Ly9kb3dubG9hZC5kb2NrZXIuY29tL2xpbnV4L3N0YXRpYy9zdGFibGUvYWFyY2g2NC9kb2NrZXItMjAuMTAuOC50Z3oKICAtIGIzMjJlOGZiYjc2ZmU3MWRmMDE5MWQ2NTA5OTEyYWMxZjE1ZDMxYjg3MjFjODE4YWY4NWI3NmM2NWY4ZmQ5YmNAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFybTY0CiAgLSA0MTU1ZjQyNDRmN2ZiNTM1YTY2MTA3MzJjNjhhNGIxYjM2YTEyMzkyY2IyODc5YTRiYjlkMTBkYWNmOWJlYTZhQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hcm02NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYXJtNjQKQ2x1c3Rlck5hbWU6IGVkdGVjaC5rOHMubG9jYWwKQ29uZmlnQmFzZTogczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwKSW5zdGFuY2VHcm91cE5hbWU6IG5vZGVzLWFwLXNvdXRoZWFzdC0xYgpJbnN0YW5jZUdyb3VwUm9sZTogTm9kZQpLdWJlbGV0Q29uZmlnOgogIGFub255bW91c0F1dGg6IGZhbHNlCiAgY2dyb3VwRHJpdmVyOiBzeXN0ZW1kCiAgY2dyb3VwUm9vdDogLwogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGNsdXN0ZXJETlM6IDEwMC42NC4wLjEwCiAgY2x1c3RlckRvbWFpbjogY2x1c3Rlci5sb2NhbAogIGVuYWJsZURlYnVnZ2luZ0hhbmRsZXJzOiB0cnVlCiAgZXZpY3Rpb25IYXJkOiBtZW1vcnkuYXZhaWxhYmxlPDEwME1pLG5vZGVmcy5hdmFpbGFibGU8MTAlLG5vZGVmcy5pbm9kZXNGcmVlPDUlLGltYWdlZnMuYXZhaWxhYmxlPDEwJSxpbWFnZWZzLmlub2Rlc0ZyZWU8NSUKICBob3N0bmFtZU92ZXJyaWRlOiAnQGF3cycKICBrdWJlY29uZmlnUGF0aDogL3Zhci9saWIva3ViZWxldC9rdWJlY29uZmlnCiAgbG9nTGV2ZWw6IDIKICBub2RlTGFiZWxzOgogICAga29wcy5rOHMuaW8vaW5zdGFuY2Vncm91cDogbm9kZXMtYXAtc291dGhlYXN0LTFiCiAgICBrdWJlcm5ldGVzLmlvL3JvbGU6IG5vZGUKICAgIG5vZGUtcm9sZS5rdWJlcm5ldGVzLmlvL25vZGU6ICIiCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKVXBkYXRlUG9saWN5OiBhdXRvbWF0aWMKY2hhbm5lbHM6Ci0gczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwvYWRkb25zL2Jvb3RzdHJhcC1jaGFubmVsLnlhbWwKCl9fRU9GX0tVQkVfRU5WCgpkb3dubG9hZC1yZWxlYXNlCmVjaG8gIj09IG5vZGV1cCBub2RlIGNvbmZpZyBkb25lID09Igo="
    iam_instance_profile = "${aws_iam_role.IAMRole11.name}"
    tags {
        k8s.io/role/node = "1"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        Name = "nodes-ap-southeast-1b.edtech.k8s.local"
        k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "node"
        aws:ec2launchtemplate:id = "lt-0ca7d671d15ae899f"
        KubernetesCluster = "edtech.k8s.local"
        k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/node = ""
        k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
        aws:ec2launchtemplate:version = "1"
        kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
        aws:autoscaling:groupName = "nodes-ap-southeast-1b.edtech.k8s.local"
    }
}

resource "aws_instance" "EC2Instance5" {
    ami = "ami-0c07cd0ceb5369def"
    instance_type = "t3.medium"
    key_name = "kubernetes.edtech.k8s.local-61:ea:d4:fe:46:60:58:76:57:c3:2f:2d:7f:aa:30:2a"
    availability_zone = "ap-southeast-1a"
    tenancy = "default"
    subnet_id = "subnet-073aadc3871ef404e"
    ebs_optimized = false
    vpc_security_group_ids = [
        "${aws_security_group.EC2SecurityGroup2.id}"
    ]
    source_dest_check = false
    ebs_block_device {
        device_name = "/dev/xvdu"
        encrypted = true
        volume_size = 20
        snapshot_id = ""
        volume_type = "gp3"
        delete_on_termination = false
    }
    ebs_block_device {
        device_name = "/dev/xvdv"
        encrypted = true
        volume_size = 20
        snapshot_id = ""
        volume_type = "gp3"
        delete_on_termination = false
    }
    root_block_device {
        volume_size = 64
        volume_type = "gp3"
        delete_on_termination = true
    }
    user_data = "IyEvYmluL2Jhc2gKc2V0IC1vIGVycmV4aXQKc2V0IC1vIG5vdW5zZXQKc2V0IC1vIHBpcGVmYWlsCgpOT0RFVVBfVVJMX0FNRDY0PWh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9ub2RldXAsaHR0cHM6Ly9naXRodWIuY29tL2t1YmVybmV0ZXMva29wcy9yZWxlYXNlcy9kb3dubG9hZC92MS4yMS4xL25vZGV1cC1saW51eC1hbWQ2NApOT0RFVVBfSEFTSF9BTUQ2ND1kYjM0ZDM4OTRlMGJhNmY5YTMxN2MzMGI1ZGUxNWRmYjQzZTFhMTkxMjhlODYxNTcyNGMwODJjNGI5ZWZkZGY0Ck5PREVVUF9VUkxfQVJNNjQ9aHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L25vZGV1cCxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvbm9kZXVwLWxpbnV4LWFybTY0Ck5PREVVUF9IQVNIX0FSTTY0PWVlZGQxYzM0MmMwMzkwMGIwOWQ3MmNjMzIzYTZkZWRiMzc4NDI3YjBmMmQ2ZGM0MzY3MDQ4ZDM2OTgzNmM3OGYKCmV4cG9ydCBBV1NfUkVHSU9OPWFwLXNvdXRoZWFzdC0xCgoKCgpzeXNjdGwgLXcgbmV0LmlwdjQudGNwX3JtZW09JzQwOTYgMTI1ODI5MTIgMTY3NzcyMTYnIHx8IHRydWUKCgpmdW5jdGlvbiBlbnN1cmUtaW5zdGFsbC1kaXIoKSB7CiAgSU5TVEFMTF9ESVI9Ii9vcHQva29wcyIKICAjIE9uIENvbnRhaW5lck9TLCB3ZSBpbnN0YWxsIHVuZGVyIC92YXIvbGliL3Rvb2xib3g7IC9vcHQgaXMgcm8gYW5kIG5vZXhlYwogIGlmIFtbIC1kIC92YXIvbGliL3Rvb2xib3ggXV07IHRoZW4KICAgIElOU1RBTExfRElSPSIvdmFyL2xpYi90b29sYm94L2tvcHMiCiAgZmkKICBta2RpciAtcCAke0lOU1RBTExfRElSfS9iaW4KICBta2RpciAtcCAke0lOU1RBTExfRElSfS9jb25mCiAgY2QgJHtJTlNUQUxMX0RJUn0KfQoKIyBSZXRyeSBhIGRvd25sb2FkIHVudGlsIHdlIGdldCBpdC4gYXJnczogbmFtZSwgc2hhLCB1cmwxLCB1cmwyLi4uCmRvd25sb2FkLW9yLWJ1c3QoKSB7CiAgbG9jYWwgLXIgZmlsZT0iJDEiCiAgbG9jYWwgLXIgaGFzaD0iJDIiCiAgc2hpZnQgMgoKICB1cmxzPSggJCogKQogIHdoaWxlIHRydWU7IGRvCiAgICBmb3IgdXJsIGluICIke3VybHNbQF19IjsgZG8KICAgICAgY29tbWFuZHM9KAogICAgICAgICJjdXJsIC1mIC0taXB2NCAtLWNvbXByZXNzZWQgLUxvICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dCAyMCAtLXJldHJ5IDYgLS1yZXRyeS1kZWxheSAxMCIKICAgICAgICAid2dldCAtLWluZXQ0LW9ubHkgLS1jb21wcmVzc2lvbj1hdXRvIC1PICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dD0yMCAtLXRyaWVzPTYgLS13YWl0PTEwIgogICAgICAgICJjdXJsIC1mIC0taXB2NCAtTG8gIiR7ZmlsZX0iIC0tY29ubmVjdC10aW1lb3V0IDIwIC0tcmV0cnkgNiAtLXJldHJ5LWRlbGF5IDEwIgogICAgICAgICJ3Z2V0IC0taW5ldDQtb25seSAtTyAiJHtmaWxlfSIgLS1jb25uZWN0LXRpbWVvdXQ9MjAgLS10cmllcz02IC0td2FpdD0xMCIKICAgICAgKQogICAgICBmb3IgY21kIGluICIke2NvbW1hbmRzW0BdfSI7IGRvCiAgICAgICAgZWNobyAiQXR0ZW1wdGluZyBkb3dubG9hZCB3aXRoOiAke2NtZH0ge3VybH0iCiAgICAgICAgaWYgISAoJHtjbWR9ICIke3VybH0iKTsgdGhlbgogICAgICAgICAgZWNobyAiPT0gRG93bmxvYWQgZmFpbGVkIHdpdGggJHtjbWR9ID09IgogICAgICAgICAgY29udGludWUKICAgICAgICBmaQogICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXSAmJiAhIHZhbGlkYXRlLWhhc2ggIiR7ZmlsZX0iICIke2hhc2h9IjsgdGhlbgogICAgICAgICAgZWNobyAiPT0gSGFzaCB2YWxpZGF0aW9uIG9mICR7dXJsfSBmYWlsZWQuIFJldHJ5aW5nLiA9PSIKICAgICAgICAgIHJtIC1mICIke2ZpbGV9IgogICAgICAgIGVsc2UKICAgICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXTsgdGhlbgogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSAoU0hBMSA9ICR7aGFzaH0pID09IgogICAgICAgICAgZWxzZQogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSA9PSIKICAgICAgICAgIGZpCiAgICAgICAgICByZXR1cm4KICAgICAgICBmaQogICAgICBkb25lCiAgICBkb25lCgogICAgZWNobyAiQWxsIGRvd25sb2FkcyBmYWlsZWQ7IHNsZWVwaW5nIGJlZm9yZSByZXRyeWluZyIKICAgIHNsZWVwIDYwCiAgZG9uZQp9Cgp2YWxpZGF0ZS1oYXNoKCkgewogIGxvY2FsIC1yIGZpbGU9IiQxIgogIGxvY2FsIC1yIGV4cGVjdGVkPSIkMiIKICBsb2NhbCBhY3R1YWwKCiAgYWN0dWFsPSQoc2hhMjU2c3VtICR7ZmlsZX0gfCBhd2sgJ3sgcHJpbnQgJDEgfScpIHx8IHRydWUKICBpZiBbWyAiJHthY3R1YWx9IiAhPSAiJHtleHBlY3RlZH0iIF1dOyB0aGVuCiAgICBlY2hvICI9PSAke2ZpbGV9IGNvcnJ1cHRlZCwgaGFzaCAke2FjdHVhbH0gZG9lc24ndCBtYXRjaCBleHBlY3RlZCAke2V4cGVjdGVkfSA9PSIKICAgIHJldHVybiAxCiAgZmkKfQoKZnVuY3Rpb24gc3BsaXQtY29tbWFzKCkgewogIGVjaG8gJDEgfCB0ciAiLCIgIlxuIgp9CgpmdW5jdGlvbiB0cnktZG93bmxvYWQtcmVsZWFzZSgpIHsKICBsb2NhbCAtciBub2RldXBfdXJscz0oICQoc3BsaXQtY29tbWFzICIke05PREVVUF9VUkx9IikgKQogIGlmIFtbIC1uICIke05PREVVUF9IQVNIOi19IiBdXTsgdGhlbgogICAgbG9jYWwgLXIgbm9kZXVwX2hhc2g9IiR7Tk9ERVVQX0hBU0h9IgogIGVsc2UKICAjIFRPRE86IFJlbW92ZT8KICAgIGVjaG8gIkRvd25sb2FkaW5nIHNoYTI1NiAobm90IGZvdW5kIGluIGVudikiCiAgICBkb3dubG9hZC1vci1idXN0IG5vZGV1cC5zaGEyNTYgIiIgIiR7bm9kZXVwX3VybHNbQF0vJS8uc2hhMjU2fSIKICAgIGxvY2FsIC1yIG5vZGV1cF9oYXNoPSQoY2F0IG5vZGV1cC5zaGEyNTYpCiAgZmkKCiAgZWNobyAiRG93bmxvYWRpbmcgbm9kZXVwICgke25vZGV1cF91cmxzW0BdfSkiCiAgZG93bmxvYWQtb3ItYnVzdCBub2RldXAgIiR7bm9kZXVwX2hhc2h9IiAiJHtub2RldXBfdXJsc1tAXX0iCgogIGNobW9kICt4IG5vZGV1cAp9CgpmdW5jdGlvbiBkb3dubG9hZC1yZWxlYXNlKCkgewogIGNhc2UgIiQodW5hbWUgLW0pIiBpbgogIHg4Nl82NCp8aT84Nl82NCp8YW1kNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FNRDY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FNRDY0fSIKICAgIDs7CiAgYWFyY2g2NCp8YXJtNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FSTTY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FSTTY0fSIKICAgIDs7CiAgKikKICAgIGVjaG8gIlVuc3VwcG9ydGVkIGhvc3QgYXJjaDogJCh1bmFtZSAtbSkiID4mMgogICAgZXhpdCAxCiAgICA7OwogIGVzYWMKCiAgIyBJbiBjYXNlIG9mIGZhaWx1cmUgY2hlY2tpbmcgaW50ZWdyaXR5IG9mIHJlbGVhc2UsIHJldHJ5LgogIGNkICR7SU5TVEFMTF9ESVJ9L2JpbgogIHVudGlsIHRyeS1kb3dubG9hZC1yZWxlYXNlOyBkbwogICAgc2xlZXAgMTUKICAgIGVjaG8gIkNvdWxkbid0IGRvd25sb2FkIHJlbGVhc2UuIFJldHJ5aW5nLi4uIgogIGRvbmUKCiAgZWNobyAiUnVubmluZyBub2RldXAiCiAgIyBXZSBjYW4ndCBydW4gaW4gdGhlIGZvcmVncm91bmQgYmVjYXVzZSBvZiBodHRwczovL2dpdGh1Yi5jb20vZG9ja2VyL2RvY2tlci9pc3N1ZXMvMjM3OTMKICAoIGNkICR7SU5TVEFMTF9ESVJ9L2JpbjsgLi9ub2RldXAgLS1pbnN0YWxsLXN5c3RlbWQtdW5pdCAtLWNvbmY9JHtJTlNUQUxMX0RJUn0vY29uZi9rdWJlX2Vudi55YW1sIC0tdj04ICApCn0KCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoKL2Jpbi9zeXN0ZW1kLW1hY2hpbmUtaWQtc2V0dXAgfHwgZWNobyAiZmFpbGVkIHRvIHNldCB1cCBlbnN1cmUgbWFjaGluZS1pZCBjb25maWd1cmVkIgoKZWNobyAiPT0gbm9kZXVwIG5vZGUgY29uZmlnIHN0YXJ0aW5nID09IgplbnN1cmUtaW5zdGFsbC1kaXIKCmNhdCA+IGNvbmYvY2x1c3Rlcl9zcGVjLnlhbWwgPDwgJ19fRU9GX0NMVVNURVJfU1BFQycKY2xvdWRDb25maWc6CiAgYXdzRUJTQ1NJRHJpdmVyOgogICAgZW5hYmxlZDogZmFsc2UKICBtYW5hZ2VTdG9yYWdlQ2xhc3NlczogdHJ1ZQpjb250YWluZXJSdW50aW1lOiBjb250YWluZXJkCmNvbnRhaW5lcmQ6CiAgY29uZmlnT3ZlcnJpZGU6IHwKICAgIHZlcnNpb24gPSAyCgogICAgW3BsdWdpbnNdCgogICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSJdCgogICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jbmldCiAgICAgICAgICBjb25mX3RlbXBsYXRlID0gIi9ldGMvY29udGFpbmVyZC9jb25maWctY25pLnRlbXBsYXRlIgoKICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZF0KCiAgICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZC5ydW50aW1lc10KCiAgICAgICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jb250YWluZXJkLnJ1bnRpbWVzLnJ1bmNdCiAgICAgICAgICAgICAgcnVudGltZV90eXBlID0gImlvLmNvbnRhaW5lcmQucnVuYy52MiIKCiAgICAgICAgICAgICAgW3BsdWdpbnMuImlvLmNvbnRhaW5lcmQuZ3JwYy52MS5jcmkiLmNvbnRhaW5lcmQucnVudGltZXMucnVuYy5vcHRpb25zXQogICAgICAgICAgICAgICAgU3lzdGVtZENncm91cCA9IHRydWUKICBsb2dMZXZlbDogaW5mbwogIHZlcnNpb246IDEuNC45CmRvY2tlcjoKICBza2lwSW5zdGFsbDogdHJ1ZQplbmNyeXB0aW9uQ29uZmlnOiBudWxsCmV0Y2RDbHVzdGVyczoKICBldmVudHM6CiAgICBjcHVSZXF1ZXN0OiAxMDBtCiAgICBtZW1vcnlSZXF1ZXN0OiAxMDBNaQogICAgdmVyc2lvbjogMy40LjEzCiAgbWFpbjoKICAgIGNwdVJlcXVlc3Q6IDIwMG0KICAgIG1lbW9yeVJlcXVlc3Q6IDEwME1pCiAgICB2ZXJzaW9uOiAzLjQuMTMKa3ViZUFQSVNlcnZlcjoKICBhbGxvd1ByaXZpbGVnZWQ6IHRydWUKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGFwaUF1ZGllbmNlczoKICAtIGt1YmVybmV0ZXMuc3ZjLmRlZmF1bHQKICBhcGlTZXJ2ZXJDb3VudDogMQogIGF1dGhvcml6YXRpb25Nb2RlOiBOb2RlLFJCQUMKICBiaW5kQWRkcmVzczogMC4wLjAuMAogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGVuYWJsZUFkbWlzc2lvblBsdWdpbnM6CiAgLSBOYW1lc3BhY2VMaWZlY3ljbGUKICAtIExpbWl0UmFuZ2VyCiAgLSBTZXJ2aWNlQWNjb3VudAogIC0gUGVyc2lzdGVudFZvbHVtZUxhYmVsCiAgLSBEZWZhdWx0U3RvcmFnZUNsYXNzCiAgLSBEZWZhdWx0VG9sZXJhdGlvblNlY29uZHMKICAtIE11dGF0aW5nQWRtaXNzaW9uV2ViaG9vawogIC0gVmFsaWRhdGluZ0FkbWlzc2lvbldlYmhvb2sKICAtIE5vZGVSZXN0cmljdGlvbgogIC0gUmVzb3VyY2VRdW90YQogIGV0Y2RTZXJ2ZXJzOgogIC0gaHR0cHM6Ly8xMjcuMC4wLjE6NDAwMQogIGV0Y2RTZXJ2ZXJzT3ZlcnJpZGVzOgogIC0gL2V2ZW50cyNodHRwczovLzEyNy4wLjAuMTo0MDAyCiAgaW1hZ2U6IGs4cy5nY3IuaW8va3ViZS1hcGlzZXJ2ZXI6djEuMjEuNQogIGt1YmVsZXRQcmVmZXJyZWRBZGRyZXNzVHlwZXM6CiAgLSBJbnRlcm5hbElQCiAgLSBIb3N0bmFtZQogIC0gRXh0ZXJuYWxJUAogIGxvZ0xldmVsOiAyCiAgcmVxdWVzdGhlYWRlckFsbG93ZWROYW1lczoKICAtIGFnZ3JlZ2F0b3IKICByZXF1ZXN0aGVhZGVyRXh0cmFIZWFkZXJQcmVmaXhlczoKICAtIFgtUmVtb3RlLUV4dHJhLQogIHJlcXVlc3RoZWFkZXJHcm91cEhlYWRlcnM6CiAgLSBYLVJlbW90ZS1Hcm91cAogIHJlcXVlc3RoZWFkZXJVc2VybmFtZUhlYWRlcnM6CiAgLSBYLVJlbW90ZS1Vc2VyCiAgc2VjdXJlUG9ydDogNDQzCiAgc2VydmljZUFjY291bnRJc3N1ZXI6IGh0dHBzOi8vYXBpLmludGVybmFsLmVkdGVjaC5rOHMubG9jYWwKICBzZXJ2aWNlQWNjb3VudEpXS1NVUkk6IGh0dHBzOi8vYXBpLmludGVybmFsLmVkdGVjaC5rOHMubG9jYWwvb3BlbmlkL3YxL2p3a3MKICBzZXJ2aWNlQ2x1c3RlcklQUmFuZ2U6IDEwMC42NC4wLjAvMTMKICBzdG9yYWdlQmFja2VuZDogZXRjZDMKa3ViZUNvbnRyb2xsZXJNYW5hZ2VyOgogIGFsbG9jYXRlTm9kZUNJRFJzOiB0cnVlCiAgYXR0YWNoRGV0YWNoUmVjb25jaWxlU3luY1BlcmlvZDogMW0wcwogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGNsdXN0ZXJDSURSOiAxMDAuOTYuMC4wLzExCiAgY2x1c3Rlck5hbWU6IGVkdGVjaC5rOHMubG9jYWwKICBjb25maWd1cmVDbG91ZFJvdXRlczogdHJ1ZQogIGltYWdlOiBrOHMuZ2NyLmlvL2t1YmUtY29udHJvbGxlci1tYW5hZ2VyOnYxLjIxLjUKICBsZWFkZXJFbGVjdGlvbjoKICAgIGxlYWRlckVsZWN0OiB0cnVlCiAgbG9nTGV2ZWw6IDIKICB1c2VTZXJ2aWNlQWNjb3VudENyZWRlbnRpYWxzOiB0cnVlCmt1YmVQcm94eToKICBjbHVzdGVyQ0lEUjogMTAwLjk2LjAuMC8xMQogIGNwdVJlcXVlc3Q6IDEwMG0KICBob3N0bmFtZU92ZXJyaWRlOiAnQGF3cycKICBpbWFnZTogazhzLmdjci5pby9rdWJlLXByb3h5OnYxLjIxLjUKICBsb2dMZXZlbDogMgprdWJlU2NoZWR1bGVyOgogIGltYWdlOiBrOHMuZ2NyLmlvL2t1YmUtc2NoZWR1bGVyOnYxLjIxLjUKICBsZWFkZXJFbGVjdGlvbjoKICAgIGxlYWRlckVsZWN0OiB0cnVlCiAgbG9nTGV2ZWw6IDIKa3ViZWxldDoKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGNncm91cERyaXZlcjogc3lzdGVtZAogIGNncm91cFJvb3Q6IC8KICBjbG91ZFByb3ZpZGVyOiBhd3MKICBjbHVzdGVyRE5TOiAxMDAuNjQuMC4xMAogIGNsdXN0ZXJEb21haW46IGNsdXN0ZXIubG9jYWwKICBlbmFibGVEZWJ1Z2dpbmdIYW5kbGVyczogdHJ1ZQogIGV2aWN0aW9uSGFyZDogbWVtb3J5LmF2YWlsYWJsZTwxMDBNaSxub2RlZnMuYXZhaWxhYmxlPDEwJSxub2RlZnMuaW5vZGVzRnJlZTw1JSxpbWFnZWZzLmF2YWlsYWJsZTwxMCUsaW1hZ2Vmcy5pbm9kZXNGcmVlPDUlCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAga3ViZWNvbmZpZ1BhdGg6IC92YXIvbGliL2t1YmVsZXQva3ViZWNvbmZpZwogIGxvZ0xldmVsOiAyCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKbWFzdGVyS3ViZWxldDoKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGNncm91cERyaXZlcjogc3lzdGVtZAogIGNncm91cFJvb3Q6IC8KICBjbG91ZFByb3ZpZGVyOiBhd3MKICBjbHVzdGVyRE5TOiAxMDAuNjQuMC4xMAogIGNsdXN0ZXJEb21haW46IGNsdXN0ZXIubG9jYWwKICBlbmFibGVEZWJ1Z2dpbmdIYW5kbGVyczogdHJ1ZQogIGV2aWN0aW9uSGFyZDogbWVtb3J5LmF2YWlsYWJsZTwxMDBNaSxub2RlZnMuYXZhaWxhYmxlPDEwJSxub2RlZnMuaW5vZGVzRnJlZTw1JSxpbWFnZWZzLmF2YWlsYWJsZTwxMCUsaW1hZ2Vmcy5pbm9kZXNGcmVlPDUlCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAga3ViZWNvbmZpZ1BhdGg6IC92YXIvbGliL2t1YmVsZXQva3ViZWNvbmZpZwogIGxvZ0xldmVsOiAyCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKICByZWdpc3RlclNjaGVkdWxhYmxlOiBmYWxzZQoKX19FT0ZfQ0xVU1RFUl9TUEVDCgpjYXQgPiBjb25mL2lnX3NwZWMueWFtbCA8PCAnX19FT0ZfSUdfU1BFQycKe30KCl9fRU9GX0lHX1NQRUMKCmNhdCA+IGNvbmYva3ViZV9lbnYueWFtbCA8PCAnX19FT0ZfS1VCRV9FTlYnCkFwaXNlcnZlckFkZGl0aW9uYWxJUHM6Ci0gYXBpLWVkdGVjaC1rOHMtbG9jYWwtNmk1bGltLTY5NTM3OTI2OS5hcC1zb3V0aGVhc3QtMS5lbGIuYW1hem9uYXdzLmNvbQpBc3NldHM6CiAgYW1kNjQ6CiAgLSA2MDBmNzBmZTBlNjkxNTFiOWQ4YWM2NWVjMTk1YmNjODQwNjg3Zjg2YmEzOTdmY2UyN2JlMWZhYWUzNTM4YTZmQGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlbGV0CiAgLSAwNjBlZGU3NTU1MGM2M2JkYzg0ZTE0ZmNjNGM4YWIzMDE3ZjdmZmMwMzJmYzRjYWMzYmYyMGQyNzRmYWIxYmU0QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlY3RsCiAgLSA5Nzc4MjQ5MzJkNTY2N2M3YTM3YWE2YTNjYmJhNDAxMDBhNjg3M2U3YmQ5N2U4M2U4YmU4MzdlM2U3YWZkMGE4QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rOHMtYXJ0aWZhY3RzLWNuaS9yZWxlYXNlL3YwLjguNy9jbmktcGx1Z2lucy1saW51eC1hbWQ2NC12MC44LjcudGd6CiAgLSA5OTExNDc5Zjg2MDEyZDZlYWI3ZTBmNTMyZGE4ZjgwN2E4YjBmNTU1ZWUwOWVmODkzNjdkOGMzMTI0MzA3M2JiQGh0dHBzOi8vZ2l0aHViLmNvbS9jb250YWluZXJkL2NvbnRhaW5lcmQvcmVsZWFzZXMvZG93bmxvYWQvdjEuNC45L2NyaS1jb250YWluZXJkLWNuaS0xLjQuOS1saW51eC1hbWQ2NC50YXIuZ3oKICAtIGE0NzFmMDQ4ZGIyZjFlMzUyMzc5MTAwYWUwZDkyY2I0NDcxMWQ4OTY5MzQxZTI4NmNiYTI2Y2Y1ODFjM2MyZTJAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FtZDY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFtZDY0CiAgLSAyOWU1NGE4OTYxNzE5MTU1ZWQyODdjMWZiYTViMDUyNGM3YTI1ZmFjNDc0YWFjMDA5YTJlNGNiN2ViYzQxZGJlQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYW1kNjQKICBhcm02NDoKICAtIDc0NmE1MzU5NTZkYjU1ODA3ZWY3MTc3MmQyYTRhZmVjNWNjNDM4MjMzZGEyMzk1MjE2N2VjMGFlYzZmZTkzN2JAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVsZXQKICAtIGZjYThkZTdlNTViNTVjY2VhYjk5MDJhYWUwMzgzN2ZiMmYxZTcyYjk3YWEwOWIyYWM5NjI2YmRiZmQwNDY2ZTRAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVjdGwKICAtIGFlMTNkN2I1YzA1YmQxODBlYTliNWI2OGY0NGJkYWE3YmZiNDEwMzRhMmVmMWQ2OGZkOGUxMjU5Nzk3ZDY0MmZAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2s4cy1hcnRpZmFjdHMtY25pL3JlbGVhc2UvdjAuOC43L2NuaS1wbHVnaW5zLWxpbnV4LWFybTY0LXYwLjguNy50Z3oKICAtIDRlYjlkNWUyYWRmNzE4Y2Q3ZWU1OWY2OTUxNzE1ZjMxMTNjOWM0ZWU0OWM3NWM5ZWZiOTc0N2YyYzM0NTdiMmJAaHR0cHM6Ly9kb3dubG9hZC5kb2NrZXIuY29tL2xpbnV4L3N0YXRpYy9zdGFibGUvYWFyY2g2NC9kb2NrZXItMjAuMTAuOC50Z3oKICAtIGIzMjJlOGZiYjc2ZmU3MWRmMDE5MWQ2NTA5OTEyYWMxZjE1ZDMxYjg3MjFjODE4YWY4NWI3NmM2NWY4ZmQ5YmNAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFybTY0CiAgLSA0MTU1ZjQyNDRmN2ZiNTM1YTY2MTA3MzJjNjhhNGIxYjM2YTEyMzkyY2IyODc5YTRiYjlkMTBkYWNmOWJlYTZhQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hcm02NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYXJtNjQKQ2x1c3Rlck5hbWU6IGVkdGVjaC5rOHMubG9jYWwKQ29uZmlnQmFzZTogczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwKSW5zdGFuY2VHcm91cE5hbWU6IG1hc3Rlci1hcC1zb3V0aGVhc3QtMWEKSW5zdGFuY2VHcm91cFJvbGU6IE1hc3RlcgpLdWJlbGV0Q29uZmlnOgogIGFub255bW91c0F1dGg6IGZhbHNlCiAgY2dyb3VwRHJpdmVyOiBzeXN0ZW1kCiAgY2dyb3VwUm9vdDogLwogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGNsdXN0ZXJETlM6IDEwMC42NC4wLjEwCiAgY2x1c3RlckRvbWFpbjogY2x1c3Rlci5sb2NhbAogIGVuYWJsZURlYnVnZ2luZ0hhbmRsZXJzOiB0cnVlCiAgZXZpY3Rpb25IYXJkOiBtZW1vcnkuYXZhaWxhYmxlPDEwME1pLG5vZGVmcy5hdmFpbGFibGU8MTAlLG5vZGVmcy5pbm9kZXNGcmVlPDUlLGltYWdlZnMuYXZhaWxhYmxlPDEwJSxpbWFnZWZzLmlub2Rlc0ZyZWU8NSUKICBob3N0bmFtZU92ZXJyaWRlOiAnQGF3cycKICBrdWJlY29uZmlnUGF0aDogL3Zhci9saWIva3ViZWxldC9rdWJlY29uZmlnCiAgbG9nTGV2ZWw6IDIKICBub2RlTGFiZWxzOgogICAga29wcy5rOHMuaW8vaW5zdGFuY2Vncm91cDogbWFzdGVyLWFwLXNvdXRoZWFzdC0xYQogICAga29wcy5rOHMuaW8va29wcy1jb250cm9sbGVyLXBraTogIiIKICAgIGt1YmVybmV0ZXMuaW8vcm9sZTogbWFzdGVyCiAgICBub2RlLXJvbGUua3ViZXJuZXRlcy5pby9jb250cm9sLXBsYW5lOiAiIgogICAgbm9kZS1yb2xlLmt1YmVybmV0ZXMuaW8vbWFzdGVyOiAiIgogICAgbm9kZS5rdWJlcm5ldGVzLmlvL2V4Y2x1ZGUtZnJvbS1leHRlcm5hbC1sb2FkLWJhbGFuY2VyczogIiIKICBub25NYXNxdWVyYWRlQ0lEUjogMTAwLjY0LjAuMC8xMAogIHBvZE1hbmlmZXN0UGF0aDogL2V0Yy9rdWJlcm5ldGVzL21hbmlmZXN0cwogIHJlZ2lzdGVyU2NoZWR1bGFibGU6IGZhbHNlClVwZGF0ZVBvbGljeTogYXV0b21hdGljCmNoYW5uZWxzOgotIHMzOi8vZWR0ZWNoLms4cy5sb2NhbC1zdGF0ZS1zdG9yZS9lZHRlY2guazhzLmxvY2FsL2FkZG9ucy9ib290c3RyYXAtY2hhbm5lbC55YW1sCmV0Y2RNYW5pZmVzdHM6Ci0gczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwvbWFuaWZlc3RzL2V0Y2QvbWFpbi55YW1sCi0gczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwvbWFuaWZlc3RzL2V0Y2QvZXZlbnRzLnlhbWwKc3RhdGljTWFuaWZlc3RzOgotIGtleToga3ViZS1hcGlzZXJ2ZXItaGVhbHRoY2hlY2sKICBwYXRoOiBtYW5pZmVzdHMvc3RhdGljL2t1YmUtYXBpc2VydmVyLWhlYWx0aGNoZWNrLnlhbWwKCl9fRU9GX0tVQkVfRU5WCgpkb3dubG9hZC1yZWxlYXNlCmVjaG8gIj09IG5vZGV1cCBub2RlIGNvbmZpZyBkb25lID09Igo="
    iam_instance_profile = "${aws_iam_role.IAMRole7.name}"
    tags {
        aws:autoscaling:groupName = "master-ap-southeast-1a.masters.edtech.k8s.local"
        aws:ec2launchtemplate:version = "1"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
        Name = "master-ap-southeast-1a.masters.edtech.k8s.local"
        k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "master"
        kops.k8s.io/instancegroup = "master-ap-southeast-1a"
        k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/master = ""
        k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/kops-controller-pki = ""
        k8s.io/role/master = "1"
        k8s.io/cluster-autoscaler/node-template/label/node.kubernetes.io/exclude-from-external-load-balancers = ""
        k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/control-plane = ""
        aws:ec2launchtemplate:id = "lt-0f8450ceaf32afaad"
        k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "master-ap-southeast-1a"
    }
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer" {
    name = "a3e6153cc6ed7427caeae85c27d954c1"
    listener {
        instance_port = 32379
        instance_protocol = "TCP"
        lb_port = 9002
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:32379"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup5.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer2" {
    name = "a643ccac57c9e487a98c51d3962ff170"
    listener {
        instance_port = 32087
        instance_protocol = "TCP"
        lb_port = 8080
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:32087"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup14.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer3" {
    name = "a3ce97d264b0649c1b3518b9f14bf9d8"
    listener {
        instance_port = 32419
        instance_protocol = "TCP"
        lb_port = 9004
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:32419"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup9.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer4" {
    name = "ace8eeb1a9fd643c4a5d693283900edb"
    listener {
        instance_port = 32038
        instance_protocol = "TCP"
        lb_port = 8080
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:32038"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup10.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer5" {
    name = "a16476faf343f4193a43cc973cbf114b"
    listener {
        instance_port = 32247
        instance_protocol = "TCP"
        lb_port = 9007
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:32247"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup12.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer6" {
    name = "a85ad48387563434bb1dd736fab7069e"
    listener {
        instance_port = 30179
        instance_protocol = "TCP"
        lb_port = 9003
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:30179"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup7.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer7" {
    name = "ac2119af8234b4bea99404b4db4c497a"
    listener {
        instance_port = 30334
        instance_protocol = "TCP"
        lb_port = 9001
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0adb94f14aebcb25e"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "TCP:30334"
        timeout = 5
        unhealthy_threshold = 6
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup13.id}"
    ]
    internal = false
}

resource "aws_elb" "ElasticLoadBalancingLoadBalancer8" {
    name = "api-edtech-k8s-local-6i5lim"
    listener {
        instance_port = 443
        instance_protocol = "TCP"
        lb_port = 443
        lb_protocol = "TCP"
    }
    subnets = [
        "subnet-052966279351b9b08",
        "subnet-073aadc3871ef404e"
    ]
    instances = [
        "i-0a39249880c3e61fe"
    ]
    health_check {
        healthy_threshold = 2
        interval = 10
        target = "SSL:443"
        timeout = 5
        unhealthy_threshold = 2
    }
    security_groups = [
        "${aws_security_group.EC2SecurityGroup11.id}"
    ]
    internal = false
}

resource "aws_autoscaling_group" "AutoScalingAutoScalingGroup" {
    name = "master-ap-southeast-1a.masters.edtech.k8s.local"
    launch_template {
        id = "lt-0f8450ceaf32afaad"
        name = "master-ap-southeast-1a.masters.edtech.k8s.local"
        version = "$Latest"
    }
    min_size = 1
    max_size = 1
    desired_capacity = 1
    default_cooldown = 300
    availability_zones = [
        "ap-southeast-1a"
    ]
    load_balancers = [
        "api-edtech-k8s-local-6i5lim"
    ]
    health_check_type = "EC2"
    health_check_grace_period = 0
    vpc_zone_identifier = [
        "subnet-073aadc3871ef404e"
    ]
    termination_policies = [
        "Default"
    ]
    service_linked_role_arn = "arn:aws:iam::162387011843:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    metrics_granularity = "1Minute"
    enabled_metrics = [
        "GroupMinSize",
        "GroupPendingInstances",
        "GroupTotalInstances",
        "GroupDesiredCapacity",
        "GroupInServiceInstances",
        "GroupMaxSize",
        "GroupStandbyInstances",
        "GroupTerminatingInstances"
    ]
    tag {
        key = "KubernetesCluster"
        value = "edtech.k8s.local"
        propagate_at_launch = true
    }
    tag {
        key = "Name"
        value = "master-ap-southeast-1a.masters.edtech.k8s.local"
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup"
        value = "master-ap-southeast-1a"
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/kops-controller-pki"
        value = ""
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role"
        value = "master"
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/control-plane"
        value = ""
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/master"
        value = ""
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/node.kubernetes.io/exclude-from-external-load-balancers"
        value = ""
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/role/master"
        value = "1"
        propagate_at_launch = true
    }
    tag {
        key = "kops.k8s.io/instancegroup"
        value = "master-ap-southeast-1a"
        propagate_at_launch = true
    }
    tag {
        key = "kubernetes.io/cluster/edtech.k8s.local"
        value = "owned"
        propagate_at_launch = true
    }
}

resource "aws_autoscaling_group" "AutoScalingAutoScalingGroup2" {
    name = "nodes-ap-southeast-1b.edtech.k8s.local"
    launch_template {
        id = "lt-0ca7d671d15ae899f"
        name = "nodes-ap-southeast-1b.edtech.k8s.local"
        version = "$Latest"
    }
    min_size = 1
    max_size = 1
    desired_capacity = 1
    default_cooldown = 300
    availability_zones = [
        "ap-southeast-1b"
    ]
    health_check_type = "EC2"
    health_check_grace_period = 0
    vpc_zone_identifier = [
        "subnet-052966279351b9b08"
    ]
    termination_policies = [
        "Default"
    ]
    service_linked_role_arn = "arn:aws:iam::162387011843:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
    metrics_granularity = "1Minute"
    enabled_metrics = [
        "GroupMaxSize",
        "GroupMinSize",
        "GroupInServiceInstances",
        "GroupStandbyInstances",
        "GroupTerminatingInstances",
        "GroupDesiredCapacity",
        "GroupTotalInstances",
        "GroupPendingInstances"
    ]
    tag {
        key = "KubernetesCluster"
        value = "edtech.k8s.local"
        propagate_at_launch = true
    }
    tag {
        key = "Name"
        value = "nodes-ap-southeast-1b.edtech.k8s.local"
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup"
        value = "nodes-ap-southeast-1b"
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role"
        value = "node"
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/node"
        value = ""
        propagate_at_launch = true
    }
    tag {
        key = "k8s.io/role/node"
        value = "1"
        propagate_at_launch = true
    }
    tag {
        key = "kops.k8s.io/instancegroup"
        value = "nodes-ap-southeast-1b"
        propagate_at_launch = true
    }
    tag {
        key = "kubernetes.io/cluster/edtech.k8s.local"
        value = "owned"
        propagate_at_launch = true
    }
}

resource "aws_security_group" "EC2SecurityGroup" {
    description = "launch-wizard-1 created 2021-09-21T10:17:34.820+05:30"
    name = "launch-wizard-1"
    tags {}
    vpc_id = "${aws_vpc.EC2VPC.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        description = ""
        protocol = "-1"
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 8090
        protocol = "tcp"
        to_port = 8090
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup2" {
    description = "Security group for masters"
    name = "${aws_iam_role.IAMRole7.name}"
    tags {
        Name = "${aws_iam_role.IAMRole7.name}"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup3.id}"
        ]
        from_port = 4003
        protocol = "tcp"
        to_port = 65535
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup3.id}"
        ]
        from_port = 2382
        protocol = "tcp"
        to_port = 4000
    }
    ingress {
        security_groups = [
            "sg-015c9ab0007b5ca48"
        ]
        protocol = "-1"
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 22
        protocol = "tcp"
        to_port = 22
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup3.id}"
        ]
        from_port = 1
        protocol = "udp"
        to_port = 65535
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup3.id}"
        ]
        from_port = 1
        protocol = "tcp"
        to_port = 2379
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup11.id}"
        ]
        from_port = 443
        protocol = "tcp"
        to_port = 443
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup3" {
    description = "Security group for nodes"
    name = "${aws_iam_role.IAMRole11.name}"
    tags {
        Name = "${aws_iam_role.IAMRole11.name}"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        security_groups = [
            "sg-0222a2f9ffc4f2cce"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup2.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup5.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup14.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup9.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup10.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup12.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup7.id}"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "${aws_security_group.EC2SecurityGroup13.id}"
        ]
        protocol = "-1"
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 22
        protocol = "tcp"
        to_port = 22
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup4" {
    description = "launch-wizard-3 created 2021-10-04T10:38:13.393+05:30"
    name = "launch-wizard-3"
    tags {}
    vpc_id = "${aws_vpc.EC2VPC.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        description = ""
        from_port = 22
        protocol = "tcp"
        to_port = 22
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup5" {
    description = "Security group for Kubernetes ELB a3e6153cc6ed7427caeae85c27d954c1 (edtech/qa-service)"
    name = "k8s-elb-a3e6153cc6ed7427caeae85c27d954c1"
    tags {
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 9002
        protocol = "tcp"
        to_port = 9002
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup6" {
    description = "launch-wizard-2 created 2021-09-29T16:15:58.567+05:30"
    name = "launch-wizard-2"
    tags {}
    vpc_id = "${aws_vpc.EC2VPC.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 22
        protocol = "tcp"
        to_port = 22
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup7" {
    description = "Security group for Kubernetes ELB a85ad48387563434bb1dd736fab7069e (edtech/interactions-service)"
    name = "k8s-elb-a85ad48387563434bb1dd736fab7069e"
    tags {
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 9003
        protocol = "tcp"
        to_port = 9003
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup8" {
    description = "default VPC security group"
    name = "default"
    tags {}
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "sg-09ca9a4912ee5f9af"
        ]
        protocol = "-1"
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup9" {
    description = "Security group for Kubernetes ELB a3ce97d264b0649c1b3518b9f14bf9d8 (edtech/user-mgmnt-service)"
    name = "k8s-elb-a3ce97d264b0649c1b3518b9f14bf9d8"
    tags {
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 9004
        protocol = "tcp"
        to_port = 9004
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup10" {
    description = "Security group for Kubernetes ELB ace8eeb1a9fd643c4a5d693283900edb (edtech/qa-elasticsearch)"
    name = "k8s-elb-ace8eeb1a9fd643c4a5d693283900edb"
    tags {
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 8080
        protocol = "tcp"
        to_port = 8080
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup11" {
    description = "Security group for api ELB"
    name = "api-elb.edtech.k8s.local"
    tags {
        Name = "api-elb.edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 443
        protocol = "tcp"
        to_port = 443
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup12" {
    description = "Security group for Kubernetes ELB a16476faf343f4193a43cc973cbf114b (edtech/gamification-service)"
    name = "k8s-elb-a16476faf343f4193a43cc973cbf114b"
    tags {
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 9007
        protocol = "tcp"
        to_port = 9007
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup13" {
    description = "Security group for Kubernetes ELB ac2119af8234b4bea99404b4db4c497a (edtech/blogs-service)"
    name = "k8s-elb-ac2119af8234b4bea99404b4db4c497a"
    tags {
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 9001
        protocol = "tcp"
        to_port = 9001
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup14" {
    description = "Security group for Kubernetes ELB a643ccac57c9e487a98c51d3962ff170 (edtech/blogs-elastic-search)"
    name = "k8s-elb-a643ccac57c9e487a98c51d3962ff170"
    tags {
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
    vpc_id = "${aws_vpc.EC2VPC2.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 8080
        protocol = "tcp"
        to_port = 8080
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3
        protocol = "icmp"
        to_port = 4
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_security_group" "EC2SecurityGroup15" {
    description = "default VPC security group"
    name = "default"
    tags {}
    vpc_id = "${aws_vpc.EC2VPC.id}"
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
    ingress {
        security_groups = [
            "sg-fd9b92b3"
        ]
        protocol = "-1"
    }
    ingress {
        cidr_blocks = [
            "101.88.250.155/32"
        ]
        from_port = 22
        protocol = "tcp"
        to_port = 22
    }
    ingress {
        cidr_blocks = [
            "101.88.250.155/32"
        ]
        from_port = 9001
        protocol = "tcp"
        to_port = 9001
    }
    ingress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        from_port = 3306
        protocol = "tcp"
        to_port = 3306
    }
    egress {
        cidr_blocks = [
            "0.0.0.0/0"
        ]
        protocol = "-1"
    }
}

resource "aws_launch_template" "EC2LaunchTemplate" {
    name = "master-ap-southeast-1a.masters.edtech.k8s.local"
    tag_specifications {
        resource_type = "instance"
        tags {
            KubernetesCluster = "edtech.k8s.local"
            k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "master-ap-southeast-1a"
            k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "master"
            k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/master = ""
            k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/control-plane = ""
            kops.k8s.io/instancegroup = "master-ap-southeast-1a"
            Name = "master-ap-southeast-1a.masters.edtech.k8s.local"
            kubernetes.io/cluster/edtech.k8s.local = "owned"
            k8s.io/cluster-autoscaler/node-template/label/node.kubernetes.io/exclude-from-external-load-balancers = ""
            k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/kops-controller-pki = ""
            k8s.io/role/master = "1"
        }
    }
    tag_specifications {
        resource_type = "volume"
        tags {
            KubernetesCluster = "edtech.k8s.local"
            k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "master-ap-southeast-1a"
            k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "master"
            k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/master = ""
            k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/control-plane = ""
            kops.k8s.io/instancegroup = "master-ap-southeast-1a"
            Name = "master-ap-southeast-1a.masters.edtech.k8s.local"
            kubernetes.io/cluster/edtech.k8s.local = "owned"
            k8s.io/cluster-autoscaler/node-template/label/node.kubernetes.io/exclude-from-external-load-balancers = ""
            k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/kops-controller-pki = ""
            k8s.io/role/master = "1"
        }
    }
    user_data = "IyEvYmluL2Jhc2gKc2V0IC1vIGVycmV4aXQKc2V0IC1vIG5vdW5zZXQKc2V0IC1vIHBpcGVmYWlsCgpOT0RFVVBfVVJMX0FNRDY0PWh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9ub2RldXAsaHR0cHM6Ly9naXRodWIuY29tL2t1YmVybmV0ZXMva29wcy9yZWxlYXNlcy9kb3dubG9hZC92MS4yMS4xL25vZGV1cC1saW51eC1hbWQ2NApOT0RFVVBfSEFTSF9BTUQ2ND1kYjM0ZDM4OTRlMGJhNmY5YTMxN2MzMGI1ZGUxNWRmYjQzZTFhMTkxMjhlODYxNTcyNGMwODJjNGI5ZWZkZGY0Ck5PREVVUF9VUkxfQVJNNjQ9aHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L25vZGV1cCxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvbm9kZXVwLWxpbnV4LWFybTY0Ck5PREVVUF9IQVNIX0FSTTY0PWVlZGQxYzM0MmMwMzkwMGIwOWQ3MmNjMzIzYTZkZWRiMzc4NDI3YjBmMmQ2ZGM0MzY3MDQ4ZDM2OTgzNmM3OGYKCmV4cG9ydCBBV1NfUkVHSU9OPWFwLXNvdXRoZWFzdC0xCgoKCgpzeXNjdGwgLXcgbmV0LmlwdjQudGNwX3JtZW09JzQwOTYgMTI1ODI5MTIgMTY3NzcyMTYnIHx8IHRydWUKCgpmdW5jdGlvbiBlbnN1cmUtaW5zdGFsbC1kaXIoKSB7CiAgSU5TVEFMTF9ESVI9Ii9vcHQva29wcyIKICAjIE9uIENvbnRhaW5lck9TLCB3ZSBpbnN0YWxsIHVuZGVyIC92YXIvbGliL3Rvb2xib3g7IC9vcHQgaXMgcm8gYW5kIG5vZXhlYwogIGlmIFtbIC1kIC92YXIvbGliL3Rvb2xib3ggXV07IHRoZW4KICAgIElOU1RBTExfRElSPSIvdmFyL2xpYi90b29sYm94L2tvcHMiCiAgZmkKICBta2RpciAtcCAke0lOU1RBTExfRElSfS9iaW4KICBta2RpciAtcCAke0lOU1RBTExfRElSfS9jb25mCiAgY2QgJHtJTlNUQUxMX0RJUn0KfQoKIyBSZXRyeSBhIGRvd25sb2FkIHVudGlsIHdlIGdldCBpdC4gYXJnczogbmFtZSwgc2hhLCB1cmwxLCB1cmwyLi4uCmRvd25sb2FkLW9yLWJ1c3QoKSB7CiAgbG9jYWwgLXIgZmlsZT0iJDEiCiAgbG9jYWwgLXIgaGFzaD0iJDIiCiAgc2hpZnQgMgoKICB1cmxzPSggJCogKQogIHdoaWxlIHRydWU7IGRvCiAgICBmb3IgdXJsIGluICIke3VybHNbQF19IjsgZG8KICAgICAgY29tbWFuZHM9KAogICAgICAgICJjdXJsIC1mIC0taXB2NCAtLWNvbXByZXNzZWQgLUxvICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dCAyMCAtLXJldHJ5IDYgLS1yZXRyeS1kZWxheSAxMCIKICAgICAgICAid2dldCAtLWluZXQ0LW9ubHkgLS1jb21wcmVzc2lvbj1hdXRvIC1PICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dD0yMCAtLXRyaWVzPTYgLS13YWl0PTEwIgogICAgICAgICJjdXJsIC1mIC0taXB2NCAtTG8gIiR7ZmlsZX0iIC0tY29ubmVjdC10aW1lb3V0IDIwIC0tcmV0cnkgNiAtLXJldHJ5LWRlbGF5IDEwIgogICAgICAgICJ3Z2V0IC0taW5ldDQtb25seSAtTyAiJHtmaWxlfSIgLS1jb25uZWN0LXRpbWVvdXQ9MjAgLS10cmllcz02IC0td2FpdD0xMCIKICAgICAgKQogICAgICBmb3IgY21kIGluICIke2NvbW1hbmRzW0BdfSI7IGRvCiAgICAgICAgZWNobyAiQXR0ZW1wdGluZyBkb3dubG9hZCB3aXRoOiAke2NtZH0ge3VybH0iCiAgICAgICAgaWYgISAoJHtjbWR9ICIke3VybH0iKTsgdGhlbgogICAgICAgICAgZWNobyAiPT0gRG93bmxvYWQgZmFpbGVkIHdpdGggJHtjbWR9ID09IgogICAgICAgICAgY29udGludWUKICAgICAgICBmaQogICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXSAmJiAhIHZhbGlkYXRlLWhhc2ggIiR7ZmlsZX0iICIke2hhc2h9IjsgdGhlbgogICAgICAgICAgZWNobyAiPT0gSGFzaCB2YWxpZGF0aW9uIG9mICR7dXJsfSBmYWlsZWQuIFJldHJ5aW5nLiA9PSIKICAgICAgICAgIHJtIC1mICIke2ZpbGV9IgogICAgICAgIGVsc2UKICAgICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXTsgdGhlbgogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSAoU0hBMSA9ICR7aGFzaH0pID09IgogICAgICAgICAgZWxzZQogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSA9PSIKICAgICAgICAgIGZpCiAgICAgICAgICByZXR1cm4KICAgICAgICBmaQogICAgICBkb25lCiAgICBkb25lCgogICAgZWNobyAiQWxsIGRvd25sb2FkcyBmYWlsZWQ7IHNsZWVwaW5nIGJlZm9yZSByZXRyeWluZyIKICAgIHNsZWVwIDYwCiAgZG9uZQp9Cgp2YWxpZGF0ZS1oYXNoKCkgewogIGxvY2FsIC1yIGZpbGU9IiQxIgogIGxvY2FsIC1yIGV4cGVjdGVkPSIkMiIKICBsb2NhbCBhY3R1YWwKCiAgYWN0dWFsPSQoc2hhMjU2c3VtICR7ZmlsZX0gfCBhd2sgJ3sgcHJpbnQgJDEgfScpIHx8IHRydWUKICBpZiBbWyAiJHthY3R1YWx9IiAhPSAiJHtleHBlY3RlZH0iIF1dOyB0aGVuCiAgICBlY2hvICI9PSAke2ZpbGV9IGNvcnJ1cHRlZCwgaGFzaCAke2FjdHVhbH0gZG9lc24ndCBtYXRjaCBleHBlY3RlZCAke2V4cGVjdGVkfSA9PSIKICAgIHJldHVybiAxCiAgZmkKfQoKZnVuY3Rpb24gc3BsaXQtY29tbWFzKCkgewogIGVjaG8gJDEgfCB0ciAiLCIgIlxuIgp9CgpmdW5jdGlvbiB0cnktZG93bmxvYWQtcmVsZWFzZSgpIHsKICBsb2NhbCAtciBub2RldXBfdXJscz0oICQoc3BsaXQtY29tbWFzICIke05PREVVUF9VUkx9IikgKQogIGlmIFtbIC1uICIke05PREVVUF9IQVNIOi19IiBdXTsgdGhlbgogICAgbG9jYWwgLXIgbm9kZXVwX2hhc2g9IiR7Tk9ERVVQX0hBU0h9IgogIGVsc2UKICAjIFRPRE86IFJlbW92ZT8KICAgIGVjaG8gIkRvd25sb2FkaW5nIHNoYTI1NiAobm90IGZvdW5kIGluIGVudikiCiAgICBkb3dubG9hZC1vci1idXN0IG5vZGV1cC5zaGEyNTYgIiIgIiR7bm9kZXVwX3VybHNbQF0vJS8uc2hhMjU2fSIKICAgIGxvY2FsIC1yIG5vZGV1cF9oYXNoPSQoY2F0IG5vZGV1cC5zaGEyNTYpCiAgZmkKCiAgZWNobyAiRG93bmxvYWRpbmcgbm9kZXVwICgke25vZGV1cF91cmxzW0BdfSkiCiAgZG93bmxvYWQtb3ItYnVzdCBub2RldXAgIiR7bm9kZXVwX2hhc2h9IiAiJHtub2RldXBfdXJsc1tAXX0iCgogIGNobW9kICt4IG5vZGV1cAp9CgpmdW5jdGlvbiBkb3dubG9hZC1yZWxlYXNlKCkgewogIGNhc2UgIiQodW5hbWUgLW0pIiBpbgogIHg4Nl82NCp8aT84Nl82NCp8YW1kNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FNRDY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FNRDY0fSIKICAgIDs7CiAgYWFyY2g2NCp8YXJtNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FSTTY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FSTTY0fSIKICAgIDs7CiAgKikKICAgIGVjaG8gIlVuc3VwcG9ydGVkIGhvc3QgYXJjaDogJCh1bmFtZSAtbSkiID4mMgogICAgZXhpdCAxCiAgICA7OwogIGVzYWMKCiAgIyBJbiBjYXNlIG9mIGZhaWx1cmUgY2hlY2tpbmcgaW50ZWdyaXR5IG9mIHJlbGVhc2UsIHJldHJ5LgogIGNkICR7SU5TVEFMTF9ESVJ9L2JpbgogIHVudGlsIHRyeS1kb3dubG9hZC1yZWxlYXNlOyBkbwogICAgc2xlZXAgMTUKICAgIGVjaG8gIkNvdWxkbid0IGRvd25sb2FkIHJlbGVhc2UuIFJldHJ5aW5nLi4uIgogIGRvbmUKCiAgZWNobyAiUnVubmluZyBub2RldXAiCiAgIyBXZSBjYW4ndCBydW4gaW4gdGhlIGZvcmVncm91bmQgYmVjYXVzZSBvZiBodHRwczovL2dpdGh1Yi5jb20vZG9ja2VyL2RvY2tlci9pc3N1ZXMvMjM3OTMKICAoIGNkICR7SU5TVEFMTF9ESVJ9L2JpbjsgLi9ub2RldXAgLS1pbnN0YWxsLXN5c3RlbWQtdW5pdCAtLWNvbmY9JHtJTlNUQUxMX0RJUn0vY29uZi9rdWJlX2Vudi55YW1sIC0tdj04ICApCn0KCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoKL2Jpbi9zeXN0ZW1kLW1hY2hpbmUtaWQtc2V0dXAgfHwgZWNobyAiZmFpbGVkIHRvIHNldCB1cCBlbnN1cmUgbWFjaGluZS1pZCBjb25maWd1cmVkIgoKZWNobyAiPT0gbm9kZXVwIG5vZGUgY29uZmlnIHN0YXJ0aW5nID09IgplbnN1cmUtaW5zdGFsbC1kaXIKCmNhdCA+IGNvbmYvY2x1c3Rlcl9zcGVjLnlhbWwgPDwgJ19fRU9GX0NMVVNURVJfU1BFQycKY2xvdWRDb25maWc6CiAgYXdzRUJTQ1NJRHJpdmVyOgogICAgZW5hYmxlZDogZmFsc2UKICBtYW5hZ2VTdG9yYWdlQ2xhc3NlczogdHJ1ZQpjb250YWluZXJSdW50aW1lOiBjb250YWluZXJkCmNvbnRhaW5lcmQ6CiAgY29uZmlnT3ZlcnJpZGU6IHwKICAgIHZlcnNpb24gPSAyCgogICAgW3BsdWdpbnNdCgogICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSJdCgogICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jbmldCiAgICAgICAgICBjb25mX3RlbXBsYXRlID0gIi9ldGMvY29udGFpbmVyZC9jb25maWctY25pLnRlbXBsYXRlIgoKICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZF0KCiAgICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZC5ydW50aW1lc10KCiAgICAgICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jb250YWluZXJkLnJ1bnRpbWVzLnJ1bmNdCiAgICAgICAgICAgICAgcnVudGltZV90eXBlID0gImlvLmNvbnRhaW5lcmQucnVuYy52MiIKCiAgICAgICAgICAgICAgW3BsdWdpbnMuImlvLmNvbnRhaW5lcmQuZ3JwYy52MS5jcmkiLmNvbnRhaW5lcmQucnVudGltZXMucnVuYy5vcHRpb25zXQogICAgICAgICAgICAgICAgU3lzdGVtZENncm91cCA9IHRydWUKICBsb2dMZXZlbDogaW5mbwogIHZlcnNpb246IDEuNC45CmRvY2tlcjoKICBza2lwSW5zdGFsbDogdHJ1ZQplbmNyeXB0aW9uQ29uZmlnOiBudWxsCmV0Y2RDbHVzdGVyczoKICBldmVudHM6CiAgICBjcHVSZXF1ZXN0OiAxMDBtCiAgICBtZW1vcnlSZXF1ZXN0OiAxMDBNaQogICAgdmVyc2lvbjogMy40LjEzCiAgbWFpbjoKICAgIGNwdVJlcXVlc3Q6IDIwMG0KICAgIG1lbW9yeVJlcXVlc3Q6IDEwME1pCiAgICB2ZXJzaW9uOiAzLjQuMTMKa3ViZUFQSVNlcnZlcjoKICBhbGxvd1ByaXZpbGVnZWQ6IHRydWUKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGFwaUF1ZGllbmNlczoKICAtIGt1YmVybmV0ZXMuc3ZjLmRlZmF1bHQKICBhcGlTZXJ2ZXJDb3VudDogMQogIGF1dGhvcml6YXRpb25Nb2RlOiBOb2RlLFJCQUMKICBiaW5kQWRkcmVzczogMC4wLjAuMAogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGVuYWJsZUFkbWlzc2lvblBsdWdpbnM6CiAgLSBOYW1lc3BhY2VMaWZlY3ljbGUKICAtIExpbWl0UmFuZ2VyCiAgLSBTZXJ2aWNlQWNjb3VudAogIC0gUGVyc2lzdGVudFZvbHVtZUxhYmVsCiAgLSBEZWZhdWx0U3RvcmFnZUNsYXNzCiAgLSBEZWZhdWx0VG9sZXJhdGlvblNlY29uZHMKICAtIE11dGF0aW5nQWRtaXNzaW9uV2ViaG9vawogIC0gVmFsaWRhdGluZ0FkbWlzc2lvbldlYmhvb2sKICAtIE5vZGVSZXN0cmljdGlvbgogIC0gUmVzb3VyY2VRdW90YQogIGV0Y2RTZXJ2ZXJzOgogIC0gaHR0cHM6Ly8xMjcuMC4wLjE6NDAwMQogIGV0Y2RTZXJ2ZXJzT3ZlcnJpZGVzOgogIC0gL2V2ZW50cyNodHRwczovLzEyNy4wLjAuMTo0MDAyCiAgaW1hZ2U6IGs4cy5nY3IuaW8va3ViZS1hcGlzZXJ2ZXI6djEuMjEuNQogIGt1YmVsZXRQcmVmZXJyZWRBZGRyZXNzVHlwZXM6CiAgLSBJbnRlcm5hbElQCiAgLSBIb3N0bmFtZQogIC0gRXh0ZXJuYWxJUAogIGxvZ0xldmVsOiAyCiAgcmVxdWVzdGhlYWRlckFsbG93ZWROYW1lczoKICAtIGFnZ3JlZ2F0b3IKICByZXF1ZXN0aGVhZGVyRXh0cmFIZWFkZXJQcmVmaXhlczoKICAtIFgtUmVtb3RlLUV4dHJhLQogIHJlcXVlc3RoZWFkZXJHcm91cEhlYWRlcnM6CiAgLSBYLVJlbW90ZS1Hcm91cAogIHJlcXVlc3RoZWFkZXJVc2VybmFtZUhlYWRlcnM6CiAgLSBYLVJlbW90ZS1Vc2VyCiAgc2VjdXJlUG9ydDogNDQzCiAgc2VydmljZUFjY291bnRJc3N1ZXI6IGh0dHBzOi8vYXBpLmludGVybmFsLmVkdGVjaC5rOHMubG9jYWwKICBzZXJ2aWNlQWNjb3VudEpXS1NVUkk6IGh0dHBzOi8vYXBpLmludGVybmFsLmVkdGVjaC5rOHMubG9jYWwvb3BlbmlkL3YxL2p3a3MKICBzZXJ2aWNlQ2x1c3RlcklQUmFuZ2U6IDEwMC42NC4wLjAvMTMKICBzdG9yYWdlQmFja2VuZDogZXRjZDMKa3ViZUNvbnRyb2xsZXJNYW5hZ2VyOgogIGFsbG9jYXRlTm9kZUNJRFJzOiB0cnVlCiAgYXR0YWNoRGV0YWNoUmVjb25jaWxlU3luY1BlcmlvZDogMW0wcwogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGNsdXN0ZXJDSURSOiAxMDAuOTYuMC4wLzExCiAgY2x1c3Rlck5hbWU6IGVkdGVjaC5rOHMubG9jYWwKICBjb25maWd1cmVDbG91ZFJvdXRlczogdHJ1ZQogIGltYWdlOiBrOHMuZ2NyLmlvL2t1YmUtY29udHJvbGxlci1tYW5hZ2VyOnYxLjIxLjUKICBsZWFkZXJFbGVjdGlvbjoKICAgIGxlYWRlckVsZWN0OiB0cnVlCiAgbG9nTGV2ZWw6IDIKICB1c2VTZXJ2aWNlQWNjb3VudENyZWRlbnRpYWxzOiB0cnVlCmt1YmVQcm94eToKICBjbHVzdGVyQ0lEUjogMTAwLjk2LjAuMC8xMQogIGNwdVJlcXVlc3Q6IDEwMG0KICBob3N0bmFtZU92ZXJyaWRlOiAnQGF3cycKICBpbWFnZTogazhzLmdjci5pby9rdWJlLXByb3h5OnYxLjIxLjUKICBsb2dMZXZlbDogMgprdWJlU2NoZWR1bGVyOgogIGltYWdlOiBrOHMuZ2NyLmlvL2t1YmUtc2NoZWR1bGVyOnYxLjIxLjUKICBsZWFkZXJFbGVjdGlvbjoKICAgIGxlYWRlckVsZWN0OiB0cnVlCiAgbG9nTGV2ZWw6IDIKa3ViZWxldDoKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGNncm91cERyaXZlcjogc3lzdGVtZAogIGNncm91cFJvb3Q6IC8KICBjbG91ZFByb3ZpZGVyOiBhd3MKICBjbHVzdGVyRE5TOiAxMDAuNjQuMC4xMAogIGNsdXN0ZXJEb21haW46IGNsdXN0ZXIubG9jYWwKICBlbmFibGVEZWJ1Z2dpbmdIYW5kbGVyczogdHJ1ZQogIGV2aWN0aW9uSGFyZDogbWVtb3J5LmF2YWlsYWJsZTwxMDBNaSxub2RlZnMuYXZhaWxhYmxlPDEwJSxub2RlZnMuaW5vZGVzRnJlZTw1JSxpbWFnZWZzLmF2YWlsYWJsZTwxMCUsaW1hZ2Vmcy5pbm9kZXNGcmVlPDUlCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAga3ViZWNvbmZpZ1BhdGg6IC92YXIvbGliL2t1YmVsZXQva3ViZWNvbmZpZwogIGxvZ0xldmVsOiAyCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKbWFzdGVyS3ViZWxldDoKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGNncm91cERyaXZlcjogc3lzdGVtZAogIGNncm91cFJvb3Q6IC8KICBjbG91ZFByb3ZpZGVyOiBhd3MKICBjbHVzdGVyRE5TOiAxMDAuNjQuMC4xMAogIGNsdXN0ZXJEb21haW46IGNsdXN0ZXIubG9jYWwKICBlbmFibGVEZWJ1Z2dpbmdIYW5kbGVyczogdHJ1ZQogIGV2aWN0aW9uSGFyZDogbWVtb3J5LmF2YWlsYWJsZTwxMDBNaSxub2RlZnMuYXZhaWxhYmxlPDEwJSxub2RlZnMuaW5vZGVzRnJlZTw1JSxpbWFnZWZzLmF2YWlsYWJsZTwxMCUsaW1hZ2Vmcy5pbm9kZXNGcmVlPDUlCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAga3ViZWNvbmZpZ1BhdGg6IC92YXIvbGliL2t1YmVsZXQva3ViZWNvbmZpZwogIGxvZ0xldmVsOiAyCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKICByZWdpc3RlclNjaGVkdWxhYmxlOiBmYWxzZQoKX19FT0ZfQ0xVU1RFUl9TUEVDCgpjYXQgPiBjb25mL2lnX3NwZWMueWFtbCA8PCAnX19FT0ZfSUdfU1BFQycKe30KCl9fRU9GX0lHX1NQRUMKCmNhdCA+IGNvbmYva3ViZV9lbnYueWFtbCA8PCAnX19FT0ZfS1VCRV9FTlYnCkFwaXNlcnZlckFkZGl0aW9uYWxJUHM6Ci0gYXBpLWVkdGVjaC1rOHMtbG9jYWwtNmk1bGltLTY5NTM3OTI2OS5hcC1zb3V0aGVhc3QtMS5lbGIuYW1hem9uYXdzLmNvbQpBc3NldHM6CiAgYW1kNjQ6CiAgLSA2MDBmNzBmZTBlNjkxNTFiOWQ4YWM2NWVjMTk1YmNjODQwNjg3Zjg2YmEzOTdmY2UyN2JlMWZhYWUzNTM4YTZmQGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlbGV0CiAgLSAwNjBlZGU3NTU1MGM2M2JkYzg0ZTE0ZmNjNGM4YWIzMDE3ZjdmZmMwMzJmYzRjYWMzYmYyMGQyNzRmYWIxYmU0QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlY3RsCiAgLSA5Nzc4MjQ5MzJkNTY2N2M3YTM3YWE2YTNjYmJhNDAxMDBhNjg3M2U3YmQ5N2U4M2U4YmU4MzdlM2U3YWZkMGE4QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rOHMtYXJ0aWZhY3RzLWNuaS9yZWxlYXNlL3YwLjguNy9jbmktcGx1Z2lucy1saW51eC1hbWQ2NC12MC44LjcudGd6CiAgLSA5OTExNDc5Zjg2MDEyZDZlYWI3ZTBmNTMyZGE4ZjgwN2E4YjBmNTU1ZWUwOWVmODkzNjdkOGMzMTI0MzA3M2JiQGh0dHBzOi8vZ2l0aHViLmNvbS9jb250YWluZXJkL2NvbnRhaW5lcmQvcmVsZWFzZXMvZG93bmxvYWQvdjEuNC45L2NyaS1jb250YWluZXJkLWNuaS0xLjQuOS1saW51eC1hbWQ2NC50YXIuZ3oKICAtIGE0NzFmMDQ4ZGIyZjFlMzUyMzc5MTAwYWUwZDkyY2I0NDcxMWQ4OTY5MzQxZTI4NmNiYTI2Y2Y1ODFjM2MyZTJAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FtZDY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFtZDY0CiAgLSAyOWU1NGE4OTYxNzE5MTU1ZWQyODdjMWZiYTViMDUyNGM3YTI1ZmFjNDc0YWFjMDA5YTJlNGNiN2ViYzQxZGJlQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYW1kNjQKICBhcm02NDoKICAtIDc0NmE1MzU5NTZkYjU1ODA3ZWY3MTc3MmQyYTRhZmVjNWNjNDM4MjMzZGEyMzk1MjE2N2VjMGFlYzZmZTkzN2JAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVsZXQKICAtIGZjYThkZTdlNTViNTVjY2VhYjk5MDJhYWUwMzgzN2ZiMmYxZTcyYjk3YWEwOWIyYWM5NjI2YmRiZmQwNDY2ZTRAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVjdGwKICAtIGFlMTNkN2I1YzA1YmQxODBlYTliNWI2OGY0NGJkYWE3YmZiNDEwMzRhMmVmMWQ2OGZkOGUxMjU5Nzk3ZDY0MmZAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2s4cy1hcnRpZmFjdHMtY25pL3JlbGVhc2UvdjAuOC43L2NuaS1wbHVnaW5zLWxpbnV4LWFybTY0LXYwLjguNy50Z3oKICAtIDRlYjlkNWUyYWRmNzE4Y2Q3ZWU1OWY2OTUxNzE1ZjMxMTNjOWM0ZWU0OWM3NWM5ZWZiOTc0N2YyYzM0NTdiMmJAaHR0cHM6Ly9kb3dubG9hZC5kb2NrZXIuY29tL2xpbnV4L3N0YXRpYy9zdGFibGUvYWFyY2g2NC9kb2NrZXItMjAuMTAuOC50Z3oKICAtIGIzMjJlOGZiYjc2ZmU3MWRmMDE5MWQ2NTA5OTEyYWMxZjE1ZDMxYjg3MjFjODE4YWY4NWI3NmM2NWY4ZmQ5YmNAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFybTY0CiAgLSA0MTU1ZjQyNDRmN2ZiNTM1YTY2MTA3MzJjNjhhNGIxYjM2YTEyMzkyY2IyODc5YTRiYjlkMTBkYWNmOWJlYTZhQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hcm02NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYXJtNjQKQ2x1c3Rlck5hbWU6IGVkdGVjaC5rOHMubG9jYWwKQ29uZmlnQmFzZTogczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwKSW5zdGFuY2VHcm91cE5hbWU6IG1hc3Rlci1hcC1zb3V0aGVhc3QtMWEKSW5zdGFuY2VHcm91cFJvbGU6IE1hc3RlcgpLdWJlbGV0Q29uZmlnOgogIGFub255bW91c0F1dGg6IGZhbHNlCiAgY2dyb3VwRHJpdmVyOiBzeXN0ZW1kCiAgY2dyb3VwUm9vdDogLwogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGNsdXN0ZXJETlM6IDEwMC42NC4wLjEwCiAgY2x1c3RlckRvbWFpbjogY2x1c3Rlci5sb2NhbAogIGVuYWJsZURlYnVnZ2luZ0hhbmRsZXJzOiB0cnVlCiAgZXZpY3Rpb25IYXJkOiBtZW1vcnkuYXZhaWxhYmxlPDEwME1pLG5vZGVmcy5hdmFpbGFibGU8MTAlLG5vZGVmcy5pbm9kZXNGcmVlPDUlLGltYWdlZnMuYXZhaWxhYmxlPDEwJSxpbWFnZWZzLmlub2Rlc0ZyZWU8NSUKICBob3N0bmFtZU92ZXJyaWRlOiAnQGF3cycKICBrdWJlY29uZmlnUGF0aDogL3Zhci9saWIva3ViZWxldC9rdWJlY29uZmlnCiAgbG9nTGV2ZWw6IDIKICBub2RlTGFiZWxzOgogICAga29wcy5rOHMuaW8vaW5zdGFuY2Vncm91cDogbWFzdGVyLWFwLXNvdXRoZWFzdC0xYQogICAga29wcy5rOHMuaW8va29wcy1jb250cm9sbGVyLXBraTogIiIKICAgIGt1YmVybmV0ZXMuaW8vcm9sZTogbWFzdGVyCiAgICBub2RlLXJvbGUua3ViZXJuZXRlcy5pby9jb250cm9sLXBsYW5lOiAiIgogICAgbm9kZS1yb2xlLmt1YmVybmV0ZXMuaW8vbWFzdGVyOiAiIgogICAgbm9kZS5rdWJlcm5ldGVzLmlvL2V4Y2x1ZGUtZnJvbS1leHRlcm5hbC1sb2FkLWJhbGFuY2VyczogIiIKICBub25NYXNxdWVyYWRlQ0lEUjogMTAwLjY0LjAuMC8xMAogIHBvZE1hbmlmZXN0UGF0aDogL2V0Yy9rdWJlcm5ldGVzL21hbmlmZXN0cwogIHJlZ2lzdGVyU2NoZWR1bGFibGU6IGZhbHNlClVwZGF0ZVBvbGljeTogYXV0b21hdGljCmNoYW5uZWxzOgotIHMzOi8vZWR0ZWNoLms4cy5sb2NhbC1zdGF0ZS1zdG9yZS9lZHRlY2guazhzLmxvY2FsL2FkZG9ucy9ib290c3RyYXAtY2hhbm5lbC55YW1sCmV0Y2RNYW5pZmVzdHM6Ci0gczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwvbWFuaWZlc3RzL2V0Y2QvbWFpbi55YW1sCi0gczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwvbWFuaWZlc3RzL2V0Y2QvZXZlbnRzLnlhbWwKc3RhdGljTWFuaWZlc3RzOgotIGtleToga3ViZS1hcGlzZXJ2ZXItaGVhbHRoY2hlY2sKICBwYXRoOiBtYW5pZmVzdHMvc3RhdGljL2t1YmUtYXBpc2VydmVyLWhlYWx0aGNoZWNrLnlhbWwKCl9fRU9GX0tVQkVfRU5WCgpkb3dubG9hZC1yZWxlYXNlCmVjaG8gIj09IG5vZGV1cCBub2RlIGNvbmZpZyBkb25lID09Igo="
    iam_instance_profile {
        name = "${aws_iam_role.IAMRole7.name}"
    }
    key_name = "kubernetes.edtech.k8s.local-61:ea:d4:fe:46:60:58:76:57:c3:2f:2d:7f:aa:30:2a"
    disable_api_termination = false
    network_interfaces {
        associate_public_ip_address = true
        delete_on_termination = true
        device_index = 0
        security_groups = [
            "${aws_security_group.EC2SecurityGroup2.id}"
        ]
    }
    image_id = "ami-0c07cd0ceb5369def"
    instance_type = "t3.medium"
    monitoring {
        enabled = false
    }
}

resource "aws_launch_template" "EC2LaunchTemplate2" {
    name = "nodes-ap-southeast-1b.edtech.k8s.local"
    tag_specifications {
        resource_type = "instance"
        tags {
            k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "node"
            k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
            k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/node = ""
            k8s.io/role/node = "1"
            kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
            Name = "nodes-ap-southeast-1b.edtech.k8s.local"
            KubernetesCluster = "edtech.k8s.local"
            kubernetes.io/cluster/edtech.k8s.local = "owned"
        }
    }
    tag_specifications {
        resource_type = "volume"
        tags {
            k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "node"
            k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
            k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/node = ""
            k8s.io/role/node = "1"
            kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
            Name = "nodes-ap-southeast-1b.edtech.k8s.local"
            KubernetesCluster = "edtech.k8s.local"
            kubernetes.io/cluster/edtech.k8s.local = "owned"
        }
    }
    user_data = "IyEvYmluL2Jhc2gKc2V0IC1vIGVycmV4aXQKc2V0IC1vIG5vdW5zZXQKc2V0IC1vIHBpcGVmYWlsCgpOT0RFVVBfVVJMX0FNRDY0PWh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9ub2RldXAsaHR0cHM6Ly9naXRodWIuY29tL2t1YmVybmV0ZXMva29wcy9yZWxlYXNlcy9kb3dubG9hZC92MS4yMS4xL25vZGV1cC1saW51eC1hbWQ2NApOT0RFVVBfSEFTSF9BTUQ2ND1kYjM0ZDM4OTRlMGJhNmY5YTMxN2MzMGI1ZGUxNWRmYjQzZTFhMTkxMjhlODYxNTcyNGMwODJjNGI5ZWZkZGY0Ck5PREVVUF9VUkxfQVJNNjQ9aHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L25vZGV1cCxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvbm9kZXVwLWxpbnV4LWFybTY0Ck5PREVVUF9IQVNIX0FSTTY0PWVlZGQxYzM0MmMwMzkwMGIwOWQ3MmNjMzIzYTZkZWRiMzc4NDI3YjBmMmQ2ZGM0MzY3MDQ4ZDM2OTgzNmM3OGYKCmV4cG9ydCBBV1NfUkVHSU9OPWFwLXNvdXRoZWFzdC0xCgoKCgpzeXNjdGwgLXcgbmV0LmlwdjQudGNwX3JtZW09JzQwOTYgMTI1ODI5MTIgMTY3NzcyMTYnIHx8IHRydWUKCgpmdW5jdGlvbiBlbnN1cmUtaW5zdGFsbC1kaXIoKSB7CiAgSU5TVEFMTF9ESVI9Ii9vcHQva29wcyIKICAjIE9uIENvbnRhaW5lck9TLCB3ZSBpbnN0YWxsIHVuZGVyIC92YXIvbGliL3Rvb2xib3g7IC9vcHQgaXMgcm8gYW5kIG5vZXhlYwogIGlmIFtbIC1kIC92YXIvbGliL3Rvb2xib3ggXV07IHRoZW4KICAgIElOU1RBTExfRElSPSIvdmFyL2xpYi90b29sYm94L2tvcHMiCiAgZmkKICBta2RpciAtcCAke0lOU1RBTExfRElSfS9iaW4KICBta2RpciAtcCAke0lOU1RBTExfRElSfS9jb25mCiAgY2QgJHtJTlNUQUxMX0RJUn0KfQoKIyBSZXRyeSBhIGRvd25sb2FkIHVudGlsIHdlIGdldCBpdC4gYXJnczogbmFtZSwgc2hhLCB1cmwxLCB1cmwyLi4uCmRvd25sb2FkLW9yLWJ1c3QoKSB7CiAgbG9jYWwgLXIgZmlsZT0iJDEiCiAgbG9jYWwgLXIgaGFzaD0iJDIiCiAgc2hpZnQgMgoKICB1cmxzPSggJCogKQogIHdoaWxlIHRydWU7IGRvCiAgICBmb3IgdXJsIGluICIke3VybHNbQF19IjsgZG8KICAgICAgY29tbWFuZHM9KAogICAgICAgICJjdXJsIC1mIC0taXB2NCAtLWNvbXByZXNzZWQgLUxvICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dCAyMCAtLXJldHJ5IDYgLS1yZXRyeS1kZWxheSAxMCIKICAgICAgICAid2dldCAtLWluZXQ0LW9ubHkgLS1jb21wcmVzc2lvbj1hdXRvIC1PICIke2ZpbGV9IiAtLWNvbm5lY3QtdGltZW91dD0yMCAtLXRyaWVzPTYgLS13YWl0PTEwIgogICAgICAgICJjdXJsIC1mIC0taXB2NCAtTG8gIiR7ZmlsZX0iIC0tY29ubmVjdC10aW1lb3V0IDIwIC0tcmV0cnkgNiAtLXJldHJ5LWRlbGF5IDEwIgogICAgICAgICJ3Z2V0IC0taW5ldDQtb25seSAtTyAiJHtmaWxlfSIgLS1jb25uZWN0LXRpbWVvdXQ9MjAgLS10cmllcz02IC0td2FpdD0xMCIKICAgICAgKQogICAgICBmb3IgY21kIGluICIke2NvbW1hbmRzW0BdfSI7IGRvCiAgICAgICAgZWNobyAiQXR0ZW1wdGluZyBkb3dubG9hZCB3aXRoOiAke2NtZH0ge3VybH0iCiAgICAgICAgaWYgISAoJHtjbWR9ICIke3VybH0iKTsgdGhlbgogICAgICAgICAgZWNobyAiPT0gRG93bmxvYWQgZmFpbGVkIHdpdGggJHtjbWR9ID09IgogICAgICAgICAgY29udGludWUKICAgICAgICBmaQogICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXSAmJiAhIHZhbGlkYXRlLWhhc2ggIiR7ZmlsZX0iICIke2hhc2h9IjsgdGhlbgogICAgICAgICAgZWNobyAiPT0gSGFzaCB2YWxpZGF0aW9uIG9mICR7dXJsfSBmYWlsZWQuIFJldHJ5aW5nLiA9PSIKICAgICAgICAgIHJtIC1mICIke2ZpbGV9IgogICAgICAgIGVsc2UKICAgICAgICAgIGlmIFtbIC1uICIke2hhc2h9IiBdXTsgdGhlbgogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSAoU0hBMSA9ICR7aGFzaH0pID09IgogICAgICAgICAgZWxzZQogICAgICAgICAgICBlY2hvICI9PSBEb3dubG9hZGVkICR7dXJsfSA9PSIKICAgICAgICAgIGZpCiAgICAgICAgICByZXR1cm4KICAgICAgICBmaQogICAgICBkb25lCiAgICBkb25lCgogICAgZWNobyAiQWxsIGRvd25sb2FkcyBmYWlsZWQ7IHNsZWVwaW5nIGJlZm9yZSByZXRyeWluZyIKICAgIHNsZWVwIDYwCiAgZG9uZQp9Cgp2YWxpZGF0ZS1oYXNoKCkgewogIGxvY2FsIC1yIGZpbGU9IiQxIgogIGxvY2FsIC1yIGV4cGVjdGVkPSIkMiIKICBsb2NhbCBhY3R1YWwKCiAgYWN0dWFsPSQoc2hhMjU2c3VtICR7ZmlsZX0gfCBhd2sgJ3sgcHJpbnQgJDEgfScpIHx8IHRydWUKICBpZiBbWyAiJHthY3R1YWx9IiAhPSAiJHtleHBlY3RlZH0iIF1dOyB0aGVuCiAgICBlY2hvICI9PSAke2ZpbGV9IGNvcnJ1cHRlZCwgaGFzaCAke2FjdHVhbH0gZG9lc24ndCBtYXRjaCBleHBlY3RlZCAke2V4cGVjdGVkfSA9PSIKICAgIHJldHVybiAxCiAgZmkKfQoKZnVuY3Rpb24gc3BsaXQtY29tbWFzKCkgewogIGVjaG8gJDEgfCB0ciAiLCIgIlxuIgp9CgpmdW5jdGlvbiB0cnktZG93bmxvYWQtcmVsZWFzZSgpIHsKICBsb2NhbCAtciBub2RldXBfdXJscz0oICQoc3BsaXQtY29tbWFzICIke05PREVVUF9VUkx9IikgKQogIGlmIFtbIC1uICIke05PREVVUF9IQVNIOi19IiBdXTsgdGhlbgogICAgbG9jYWwgLXIgbm9kZXVwX2hhc2g9IiR7Tk9ERVVQX0hBU0h9IgogIGVsc2UKICAjIFRPRE86IFJlbW92ZT8KICAgIGVjaG8gIkRvd25sb2FkaW5nIHNoYTI1NiAobm90IGZvdW5kIGluIGVudikiCiAgICBkb3dubG9hZC1vci1idXN0IG5vZGV1cC5zaGEyNTYgIiIgIiR7bm9kZXVwX3VybHNbQF0vJS8uc2hhMjU2fSIKICAgIGxvY2FsIC1yIG5vZGV1cF9oYXNoPSQoY2F0IG5vZGV1cC5zaGEyNTYpCiAgZmkKCiAgZWNobyAiRG93bmxvYWRpbmcgbm9kZXVwICgke25vZGV1cF91cmxzW0BdfSkiCiAgZG93bmxvYWQtb3ItYnVzdCBub2RldXAgIiR7bm9kZXVwX2hhc2h9IiAiJHtub2RldXBfdXJsc1tAXX0iCgogIGNobW9kICt4IG5vZGV1cAp9CgpmdW5jdGlvbiBkb3dubG9hZC1yZWxlYXNlKCkgewogIGNhc2UgIiQodW5hbWUgLW0pIiBpbgogIHg4Nl82NCp8aT84Nl82NCp8YW1kNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FNRDY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FNRDY0fSIKICAgIDs7CiAgYWFyY2g2NCp8YXJtNjQqKQogICAgTk9ERVVQX1VSTD0iJHtOT0RFVVBfVVJMX0FSTTY0fSIKICAgIE5PREVVUF9IQVNIPSIke05PREVVUF9IQVNIX0FSTTY0fSIKICAgIDs7CiAgKikKICAgIGVjaG8gIlVuc3VwcG9ydGVkIGhvc3QgYXJjaDogJCh1bmFtZSAtbSkiID4mMgogICAgZXhpdCAxCiAgICA7OwogIGVzYWMKCiAgIyBJbiBjYXNlIG9mIGZhaWx1cmUgY2hlY2tpbmcgaW50ZWdyaXR5IG9mIHJlbGVhc2UsIHJldHJ5LgogIGNkICR7SU5TVEFMTF9ESVJ9L2JpbgogIHVudGlsIHRyeS1kb3dubG9hZC1yZWxlYXNlOyBkbwogICAgc2xlZXAgMTUKICAgIGVjaG8gIkNvdWxkbid0IGRvd25sb2FkIHJlbGVhc2UuIFJldHJ5aW5nLi4uIgogIGRvbmUKCiAgZWNobyAiUnVubmluZyBub2RldXAiCiAgIyBXZSBjYW4ndCBydW4gaW4gdGhlIGZvcmVncm91bmQgYmVjYXVzZSBvZiBodHRwczovL2dpdGh1Yi5jb20vZG9ja2VyL2RvY2tlci9pc3N1ZXMvMjM3OTMKICAoIGNkICR7SU5TVEFMTF9ESVJ9L2JpbjsgLi9ub2RldXAgLS1pbnN0YWxsLXN5c3RlbWQtdW5pdCAtLWNvbmY9JHtJTlNUQUxMX0RJUn0vY29uZi9rdWJlX2Vudi55YW1sIC0tdj04ICApCn0KCiMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIwoKL2Jpbi9zeXN0ZW1kLW1hY2hpbmUtaWQtc2V0dXAgfHwgZWNobyAiZmFpbGVkIHRvIHNldCB1cCBlbnN1cmUgbWFjaGluZS1pZCBjb25maWd1cmVkIgoKZWNobyAiPT0gbm9kZXVwIG5vZGUgY29uZmlnIHN0YXJ0aW5nID09IgplbnN1cmUtaW5zdGFsbC1kaXIKCmNhdCA+IGNvbmYvY2x1c3Rlcl9zcGVjLnlhbWwgPDwgJ19fRU9GX0NMVVNURVJfU1BFQycKY2xvdWRDb25maWc6CiAgYXdzRUJTQ1NJRHJpdmVyOgogICAgZW5hYmxlZDogZmFsc2UKICBtYW5hZ2VTdG9yYWdlQ2xhc3NlczogdHJ1ZQpjb250YWluZXJSdW50aW1lOiBjb250YWluZXJkCmNvbnRhaW5lcmQ6CiAgY29uZmlnT3ZlcnJpZGU6IHwKICAgIHZlcnNpb24gPSAyCgogICAgW3BsdWdpbnNdCgogICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSJdCgogICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jbmldCiAgICAgICAgICBjb25mX3RlbXBsYXRlID0gIi9ldGMvY29udGFpbmVyZC9jb25maWctY25pLnRlbXBsYXRlIgoKICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZF0KCiAgICAgICAgICBbcGx1Z2lucy4iaW8uY29udGFpbmVyZC5ncnBjLnYxLmNyaSIuY29udGFpbmVyZC5ydW50aW1lc10KCiAgICAgICAgICAgIFtwbHVnaW5zLiJpby5jb250YWluZXJkLmdycGMudjEuY3JpIi5jb250YWluZXJkLnJ1bnRpbWVzLnJ1bmNdCiAgICAgICAgICAgICAgcnVudGltZV90eXBlID0gImlvLmNvbnRhaW5lcmQucnVuYy52MiIKCiAgICAgICAgICAgICAgW3BsdWdpbnMuImlvLmNvbnRhaW5lcmQuZ3JwYy52MS5jcmkiLmNvbnRhaW5lcmQucnVudGltZXMucnVuYy5vcHRpb25zXQogICAgICAgICAgICAgICAgU3lzdGVtZENncm91cCA9IHRydWUKICBsb2dMZXZlbDogaW5mbwogIHZlcnNpb246IDEuNC45CmRvY2tlcjoKICBza2lwSW5zdGFsbDogdHJ1ZQprdWJlUHJveHk6CiAgY2x1c3RlckNJRFI6IDEwMC45Ni4wLjAvMTEKICBjcHVSZXF1ZXN0OiAxMDBtCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAgaW1hZ2U6IGs4cy5nY3IuaW8va3ViZS1wcm94eTp2MS4yMS41CiAgbG9nTGV2ZWw6IDIKa3ViZWxldDoKICBhbm9ueW1vdXNBdXRoOiBmYWxzZQogIGNncm91cERyaXZlcjogc3lzdGVtZAogIGNncm91cFJvb3Q6IC8KICBjbG91ZFByb3ZpZGVyOiBhd3MKICBjbHVzdGVyRE5TOiAxMDAuNjQuMC4xMAogIGNsdXN0ZXJEb21haW46IGNsdXN0ZXIubG9jYWwKICBlbmFibGVEZWJ1Z2dpbmdIYW5kbGVyczogdHJ1ZQogIGV2aWN0aW9uSGFyZDogbWVtb3J5LmF2YWlsYWJsZTwxMDBNaSxub2RlZnMuYXZhaWxhYmxlPDEwJSxub2RlZnMuaW5vZGVzRnJlZTw1JSxpbWFnZWZzLmF2YWlsYWJsZTwxMCUsaW1hZ2Vmcy5pbm9kZXNGcmVlPDUlCiAgaG9zdG5hbWVPdmVycmlkZTogJ0Bhd3MnCiAga3ViZWNvbmZpZ1BhdGg6IC92YXIvbGliL2t1YmVsZXQva3ViZWNvbmZpZwogIGxvZ0xldmVsOiAyCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKCl9fRU9GX0NMVVNURVJfU1BFQwoKY2F0ID4gY29uZi9pZ19zcGVjLnlhbWwgPDwgJ19fRU9GX0lHX1NQRUMnCnt9CgpfX0VPRl9JR19TUEVDCgpjYXQgPiBjb25mL2t1YmVfZW52LnlhbWwgPDwgJ19fRU9GX0tVQkVfRU5WJwpBc3NldHM6CiAgYW1kNjQ6CiAgLSA2MDBmNzBmZTBlNjkxNTFiOWQ4YWM2NWVjMTk1YmNjODQwNjg3Zjg2YmEzOTdmY2UyN2JlMWZhYWUzNTM4YTZmQGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlbGV0CiAgLSAwNjBlZGU3NTU1MGM2M2JkYzg0ZTE0ZmNjNGM4YWIzMDE3ZjdmZmMwMzJmYzRjYWMzYmYyMGQyNzRmYWIxYmU0QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rdWJlcm5ldGVzLXJlbGVhc2UvcmVsZWFzZS92MS4yMS41L2Jpbi9saW51eC9hbWQ2NC9rdWJlY3RsCiAgLSA5Nzc4MjQ5MzJkNTY2N2M3YTM3YWE2YTNjYmJhNDAxMDBhNjg3M2U3YmQ5N2U4M2U4YmU4MzdlM2U3YWZkMGE4QGh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9rOHMtYXJ0aWZhY3RzLWNuaS9yZWxlYXNlL3YwLjguNy9jbmktcGx1Z2lucy1saW51eC1hbWQ2NC12MC44LjcudGd6CiAgLSA5OTExNDc5Zjg2MDEyZDZlYWI3ZTBmNTMyZGE4ZjgwN2E4YjBmNTU1ZWUwOWVmODkzNjdkOGMzMTI0MzA3M2JiQGh0dHBzOi8vZ2l0aHViLmNvbS9jb250YWluZXJkL2NvbnRhaW5lcmQvcmVsZWFzZXMvZG93bmxvYWQvdjEuNC45L2NyaS1jb250YWluZXJkLWNuaS0xLjQuOS1saW51eC1hbWQ2NC50YXIuZ3oKICAtIGE0NzFmMDQ4ZGIyZjFlMzUyMzc5MTAwYWUwZDkyY2I0NDcxMWQ4OTY5MzQxZTI4NmNiYTI2Y2Y1ODFjM2MyZTJAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FtZDY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFtZDY0CiAgLSAyOWU1NGE4OTYxNzE5MTU1ZWQyODdjMWZiYTViMDUyNGM3YTI1ZmFjNDc0YWFjMDA5YTJlNGNiN2ViYzQxZGJlQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hbWQ2NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYW1kNjQKICBhcm02NDoKICAtIDc0NmE1MzU5NTZkYjU1ODA3ZWY3MTc3MmQyYTRhZmVjNWNjNDM4MjMzZGEyMzk1MjE2N2VjMGFlYzZmZTkzN2JAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVsZXQKICAtIGZjYThkZTdlNTViNTVjY2VhYjk5MDJhYWUwMzgzN2ZiMmYxZTcyYjk3YWEwOWIyYWM5NjI2YmRiZmQwNDY2ZTRAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2t1YmVybmV0ZXMtcmVsZWFzZS9yZWxlYXNlL3YxLjIxLjUvYmluL2xpbnV4L2FybTY0L2t1YmVjdGwKICAtIGFlMTNkN2I1YzA1YmQxODBlYTliNWI2OGY0NGJkYWE3YmZiNDEwMzRhMmVmMWQ2OGZkOGUxMjU5Nzk3ZDY0MmZAaHR0cHM6Ly9zdG9yYWdlLmdvb2dsZWFwaXMuY29tL2s4cy1hcnRpZmFjdHMtY25pL3JlbGVhc2UvdjAuOC43L2NuaS1wbHVnaW5zLWxpbnV4LWFybTY0LXYwLjguNy50Z3oKICAtIDRlYjlkNWUyYWRmNzE4Y2Q3ZWU1OWY2OTUxNzE1ZjMxMTNjOWM0ZWU0OWM3NWM5ZWZiOTc0N2YyYzM0NTdiMmJAaHR0cHM6Ly9kb3dubG9hZC5kb2NrZXIuY29tL2xpbnV4L3N0YXRpYy9zdGFibGUvYWFyY2g2NC9kb2NrZXItMjAuMTAuOC50Z3oKICAtIGIzMjJlOGZiYjc2ZmU3MWRmMDE5MWQ2NTA5OTEyYWMxZjE1ZDMxYjg3MjFjODE4YWY4NWI3NmM2NWY4ZmQ5YmNAaHR0cHM6Ly9hcnRpZmFjdHMuazhzLmlvL2JpbmFyaWVzL2tvcHMvMS4yMS4xL2xpbnV4L2FybTY0L3Byb3Rva3ViZSxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvcHJvdG9rdWJlLWxpbnV4LWFybTY0CiAgLSA0MTU1ZjQyNDRmN2ZiNTM1YTY2MTA3MzJjNjhhNGIxYjM2YTEyMzkyY2IyODc5YTRiYjlkMTBkYWNmOWJlYTZhQGh0dHBzOi8vYXJ0aWZhY3RzLms4cy5pby9iaW5hcmllcy9rb3BzLzEuMjEuMS9saW51eC9hcm02NC9jaGFubmVscyxodHRwczovL2dpdGh1Yi5jb20va3ViZXJuZXRlcy9rb3BzL3JlbGVhc2VzL2Rvd25sb2FkL3YxLjIxLjEvY2hhbm5lbHMtbGludXgtYXJtNjQKQ2x1c3Rlck5hbWU6IGVkdGVjaC5rOHMubG9jYWwKQ29uZmlnQmFzZTogczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwKSW5zdGFuY2VHcm91cE5hbWU6IG5vZGVzLWFwLXNvdXRoZWFzdC0xYgpJbnN0YW5jZUdyb3VwUm9sZTogTm9kZQpLdWJlbGV0Q29uZmlnOgogIGFub255bW91c0F1dGg6IGZhbHNlCiAgY2dyb3VwRHJpdmVyOiBzeXN0ZW1kCiAgY2dyb3VwUm9vdDogLwogIGNsb3VkUHJvdmlkZXI6IGF3cwogIGNsdXN0ZXJETlM6IDEwMC42NC4wLjEwCiAgY2x1c3RlckRvbWFpbjogY2x1c3Rlci5sb2NhbAogIGVuYWJsZURlYnVnZ2luZ0hhbmRsZXJzOiB0cnVlCiAgZXZpY3Rpb25IYXJkOiBtZW1vcnkuYXZhaWxhYmxlPDEwME1pLG5vZGVmcy5hdmFpbGFibGU8MTAlLG5vZGVmcy5pbm9kZXNGcmVlPDUlLGltYWdlZnMuYXZhaWxhYmxlPDEwJSxpbWFnZWZzLmlub2Rlc0ZyZWU8NSUKICBob3N0bmFtZU92ZXJyaWRlOiAnQGF3cycKICBrdWJlY29uZmlnUGF0aDogL3Zhci9saWIva3ViZWxldC9rdWJlY29uZmlnCiAgbG9nTGV2ZWw6IDIKICBub2RlTGFiZWxzOgogICAga29wcy5rOHMuaW8vaW5zdGFuY2Vncm91cDogbm9kZXMtYXAtc291dGhlYXN0LTFiCiAgICBrdWJlcm5ldGVzLmlvL3JvbGU6IG5vZGUKICAgIG5vZGUtcm9sZS5rdWJlcm5ldGVzLmlvL25vZGU6ICIiCiAgbm9uTWFzcXVlcmFkZUNJRFI6IDEwMC42NC4wLjAvMTAKICBwb2RNYW5pZmVzdFBhdGg6IC9ldGMva3ViZXJuZXRlcy9tYW5pZmVzdHMKVXBkYXRlUG9saWN5OiBhdXRvbWF0aWMKY2hhbm5lbHM6Ci0gczM6Ly9lZHRlY2guazhzLmxvY2FsLXN0YXRlLXN0b3JlL2VkdGVjaC5rOHMubG9jYWwvYWRkb25zL2Jvb3RzdHJhcC1jaGFubmVsLnlhbWwKCl9fRU9GX0tVQkVfRU5WCgpkb3dubG9hZC1yZWxlYXNlCmVjaG8gIj09IG5vZGV1cCBub2RlIGNvbmZpZyBkb25lID09Igo="
    iam_instance_profile {
        name = "${aws_iam_role.IAMRole11.name}"
    }
    key_name = "kubernetes.edtech.k8s.local-61:ea:d4:fe:46:60:58:76:57:c3:2f:2d:7f:aa:30:2a"
    disable_api_termination = false
    network_interfaces {
        associate_public_ip_address = true
        delete_on_termination = true
        device_index = 0
        security_groups = [
            "${aws_security_group.EC2SecurityGroup3.id}"
        ]
    }
    image_id = "ami-0c07cd0ceb5369def"
    instance_type = "t3.medium"
    monitoring {
        enabled = false
    }
}

resource "aws_ebs_volume" "EC2Volume" {
    availability_zone = "ap-southeast-1b"
    encrypted = true
    size = 128
    type = "gp3"
    snapshot_id = "snap-05d55fa71827aa54e"
    kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/8ee1321d-6c6d-4b97-a85c-16a1d700783b"
    tags {
        KubernetesCluster = "edtech.k8s.local"
        k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
        Name = "nodes-ap-southeast-1b.edtech.k8s.local"
        k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "node"
        k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/node = ""
        k8s.io/role/node = "1"
        kops.k8s.io/instancegroup = "nodes-ap-southeast-1b"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
}

resource "aws_ebs_volume" "EC2Volume2" {
    availability_zone = "ap-southeast-1b"
    encrypted = false
    size = 8
    type = "gp2"
    tags {
        Name = "edtech.k8s.local-dynamic-pvc-08f0191d-6d68-4932-8fe5-6aecfcb5f1c5"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        kubernetes.io/created-for/pv/name = "pvc-08f0191d-6d68-4932-8fe5-6aecfcb5f1c5"
        kubernetes.io/created-for/pvc/name = "prometheus-server"
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/created-for/pvc/namespace = "prometheus"
    }
}

resource "aws_ebs_volume" "EC2Volume3" {
    availability_zone = "ap-southeast-1b"
    encrypted = false
    size = 2
    type = "gp2"
    tags {
        kubernetes.io/created-for/pvc/name = "prometheus-alertmanager"
        Name = "edtech.k8s.local-dynamic-pvc-e21be655-1b18-4fe1-a4cc-4d0e2d712089"
        kubernetes.io/created-for/pvc/namespace = "prometheus"
        kubernetes.io/created-for/pv/name = "pvc-e21be655-1b18-4fe1-a4cc-4d0e2d712089"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        KubernetesCluster = "edtech.k8s.local"
    }
}

resource "aws_ebs_volume" "EC2Volume4" {
    availability_zone = "ap-southeast-1a"
    encrypted = false
    size = 50
    type = "gp2"
    snapshot_id = "snap-003ade24acdc81240"
    tags {}
}

resource "aws_ebs_volume" "EC2Volume5" {
    availability_zone = "ap-southeast-1a"
    encrypted = false
    size = 8
    type = "gp2"
    snapshot_id = "snap-003ade24acdc81240"
    tags {}
}

resource "aws_ebs_volume" "EC2Volume6" {
    availability_zone = "ap-southeast-1a"
    encrypted = false
    size = 8
    type = "gp2"
    snapshot_id = "snap-003ade24acdc81240"
    tags {}
}

resource "aws_ebs_volume" "EC2Volume7" {
    availability_zone = "ap-southeast-1a"
    encrypted = true
    size = 20
    type = "gp3"
    kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/8ee1321d-6c6d-4b97-a85c-16a1d700783b"
    tags {
        k8s.io/etcd/main = "a/a"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        k8s.io/role/master = "1"
        KubernetesCluster = "edtech.k8s.local"
        Name = "a.etcd-main.edtech.k8s.local"
    }
}

resource "aws_ebs_volume" "EC2Volume8" {
    availability_zone = "ap-southeast-1a"
    encrypted = true
    size = 20
    type = "gp3"
    kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/8ee1321d-6c6d-4b97-a85c-16a1d700783b"
    tags {
        Name = "a.etcd-events.edtech.k8s.local"
        k8s.io/role/master = "1"
        KubernetesCluster = "edtech.k8s.local"
        k8s.io/etcd/events = "a/a"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
    }
}

resource "aws_ebs_volume" "EC2Volume9" {
    availability_zone = "ap-southeast-1a"
    encrypted = true
    size = 64
    type = "gp3"
    snapshot_id = "snap-05d55fa71827aa54e"
    kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/8ee1321d-6c6d-4b97-a85c-16a1d700783b"
    tags {
        k8s.io/cluster-autoscaler/node-template/label/kubernetes.io/role = "master"
        k8s.io/cluster-autoscaler/node-template/label/node.kubernetes.io/exclude-from-external-load-balancers = ""
        Name = "master-ap-southeast-1a.masters.edtech.k8s.local"
        KubernetesCluster = "edtech.k8s.local"
        kubernetes.io/cluster/edtech.k8s.local = "owned"
        k8s.io/role/master = "1"
        k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/instancegroup = "master-ap-southeast-1a"
        kops.k8s.io/instancegroup = "master-ap-southeast-1a"
        k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/master = ""
        k8s.io/cluster-autoscaler/node-template/label/node-role.kubernetes.io/control-plane = ""
        k8s.io/cluster-autoscaler/node-template/label/kops.k8s.io/kops-controller-pki = ""
    }
}

resource "aws_volume_attachment" "EC2VolumeAttachment" {
    volume_id = "vol-0b3883b4488e3d160"
    instance_id = "i-0adb94f14aebcb25e"
    device_name = "/dev/sda1"
}

resource "aws_volume_attachment" "EC2VolumeAttachment2" {
    volume_id = "vol-0a46e332493a7d15c"
    instance_id = "i-0adb94f14aebcb25e"
    device_name = "/dev/xvdbl"
}

resource "aws_volume_attachment" "EC2VolumeAttachment3" {
    volume_id = "vol-03883e798ebb77f95"
    instance_id = "i-0adb94f14aebcb25e"
    device_name = "/dev/xvdbb"
}

resource "aws_volume_attachment" "EC2VolumeAttachment4" {
    volume_id = "vol-0b4f6e8779c10bed2"
    instance_id = "i-0f94d53b470d0ee30"
    device_name = "/dev/xvda"
}

resource "aws_volume_attachment" "EC2VolumeAttachment5" {
    volume_id = "vol-07496c295f4fcc7cf"
    instance_id = "i-06b4ad361ba0bdf85"
    device_name = "/dev/xvda"
}

resource "aws_volume_attachment" "EC2VolumeAttachment6" {
    volume_id = "vol-06d9b8bf2754e7f87"
    instance_id = "i-098c0d44a89ca86f6"
    device_name = "/dev/xvda"
}

resource "aws_volume_attachment" "EC2VolumeAttachment7" {
    volume_id = "vol-069323c79c924f052"
    instance_id = "i-0a39249880c3e61fe"
    device_name = "/dev/xvdv"
}

resource "aws_volume_attachment" "EC2VolumeAttachment8" {
    volume_id = "vol-07289ff28c0b1bb9f"
    instance_id = "i-0a39249880c3e61fe"
    device_name = "/dev/xvdu"
}

resource "aws_volume_attachment" "EC2VolumeAttachment9" {
    volume_id = "vol-0810031c6bf010c65"
    instance_id = "i-0a39249880c3e61fe"
    device_name = "/dev/sda1"
}

resource "aws_network_interface" "EC2NetworkInterface" {
    description = "ELB ace8eeb1a9fd643c4a5d693283900edb"
    private_ips = [
        "172.20.38.134"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup10.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface2" {
    description = "ELB a16476faf343f4193a43cc973cbf114b"
    private_ips = [
        "172.20.57.189"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup12.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface3" {
    description = "RDSNetworkInterface"
    private_ips = [
        "172.31.23.115"
    ]
    subnet_id = "subnet-fb80059d"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup15.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface4" {
    description = ""
    private_ips = [
        "172.31.29.166"
    ]
    subnet_id = "subnet-fb80059d"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface5" {
    description = "ELB a643ccac57c9e487a98c51d3962ff170"
    private_ips = [
        "172.20.50.167"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup14.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface6" {
    description = ""
    private_ips = [
        "172.20.35.112"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = false
    security_groups = [
        "${aws_security_group.EC2SecurityGroup2.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface7" {
    description = ""
    private_ips = [
        "172.20.84.149"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = false
    security_groups = [
        "${aws_security_group.EC2SecurityGroup3.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface8" {
    description = ""
    private_ips = [
        "172.31.27.212"
    ]
    subnet_id = "subnet-fb80059d"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup15.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface9" {
    description = "ELB a3ce97d264b0649c1b3518b9f14bf9d8"
    private_ips = [
        "172.20.84.148"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup9.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface10" {
    description = "ELB api-edtech-k8s-local-6i5lim"
    private_ips = [
        "172.20.56.90"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup11.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface11" {
    description = "ELB api-edtech-k8s-local-6i5lim"
    private_ips = [
        "172.20.87.90"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup11.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface12" {
    description = "DAX mydaxcluster-a"
    private_ips = [
        "172.20.40.124"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup8.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface13" {
    description = "ELB a3ce97d264b0649c1b3518b9f14bf9d8"
    private_ips = [
        "172.20.57.107"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup9.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface14" {
    description = "ELB ac2119af8234b4bea99404b4db4c497a"
    private_ips = [
        "172.20.71.163"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup13.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface15" {
    description = "ELB ace8eeb1a9fd643c4a5d693283900edb"
    private_ips = [
        "172.20.92.210"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup10.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface16" {
    description = "ELB a16476faf343f4193a43cc973cbf114b"
    private_ips = [
        "172.20.81.34"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup12.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface17" {
    description = "ELB a85ad48387563434bb1dd736fab7069e"
    private_ips = [
        "172.20.43.66"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup7.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface18" {
    description = "ELB a3e6153cc6ed7427caeae85c27d954c1"
    private_ips = [
        "172.20.61.8"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup5.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface19" {
    description = "ELB a643ccac57c9e487a98c51d3962ff170"
    private_ips = [
        "172.20.91.5"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup14.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface20" {
    description = "ELB a85ad48387563434bb1dd736fab7069e"
    private_ips = [
        "172.20.84.131"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup7.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface21" {
    description = "DAX mydaxcluster-b"
    private_ips = [
        "172.20.94.86"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup8.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface22" {
    description = "ELB a3e6153cc6ed7427caeae85c27d954c1"
    private_ips = [
        "172.20.88.177"
    ]
    subnet_id = "subnet-052966279351b9b08"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup5.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface23" {
    description = ""
    private_ips = [
        "172.31.31.216"
    ]
    subnet_id = "subnet-fb80059d"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup6.id}"
    ]
}

resource "aws_network_interface" "EC2NetworkInterface24" {
    description = "ELB ac2119af8234b4bea99404b4db4c497a"
    private_ips = [
        "172.20.60.84"
    ]
    subnet_id = "subnet-073aadc3871ef404e"
    source_dest_check = true
    security_groups = [
        "${aws_security_group.EC2SecurityGroup13.id}"
    ]
}

resource "aws_network_interface_attachment" "EC2NetworkInterfaceAttachment" {
    network_interface_id = "eni-0c7d5f262bc2dbbd9"
    device_index = 0
    instance_id = "i-0f94d53b470d0ee30"
}

resource "aws_network_interface_attachment" "EC2NetworkInterfaceAttachment2" {
    network_interface_id = "eni-011ff5a0d87b1c686"
    device_index = 0
    instance_id = "i-0a39249880c3e61fe"
}

resource "aws_network_interface_attachment" "EC2NetworkInterfaceAttachment3" {
    network_interface_id = "eni-023f648148879cd12"
    device_index = 0
    instance_id = "i-0adb94f14aebcb25e"
}

resource "aws_network_interface_attachment" "EC2NetworkInterfaceAttachment4" {
    network_interface_id = "eni-09b414dfd54944c60"
    device_index = 0
    instance_id = "i-098c0d44a89ca86f6"
}

resource "aws_network_interface_attachment" "EC2NetworkInterfaceAttachment5" {
    network_interface_id = "eni-09a72c6f9f6651ebf"
    device_index = 0
    instance_id = "i-06b4ad361ba0bdf85"
}

resource "aws_flow_log" "EC2FlowLog" {
    traffic_type = "ALL"
    log_destination_type = "s3"
    log_destination = "arn:aws:s3:::vpc-k8s-flow-log"
    vpc_id = "${aws_vpc.EC2VPC2.id}"
}

resource "aws_key_pair" "EC2KeyPair" {
    public_key = "REPLACEME"
    key_name = "CLoudWatch_Sample"
}

resource "aws_key_pair" "EC2KeyPair2" {
    public_key = "REPLACEME"
    key_name = "DAXKeypair"
}

resource "aws_key_pair" "EC2KeyPair3" {
    public_key = "REPLACEME"
    key_name = "deployment-ec2-blogs"
}

resource "aws_key_pair" "EC2KeyPair4" {
    public_key = "REPLACEME"
    key_name = "edtech-key"
}

resource "aws_key_pair" "EC2KeyPair5" {
    public_key = "REPLACEME"
    key_name = "kubernetes.edtech.k8s.local-61:ea:d4:fe:46:60:58:76:57:c3:2f:2d:7f:aa:30:2a"
}

resource "aws_lambda_function" "LambdaFunction" {
    description = ""
    function_name = "blog-es-function"
    handler = "index.handler"
    architectures = [
        "x86_64"
    ]
    s3_bucket = "awslambda-ap-se-1-tasks"
    s3_key = "/snapshots/162387011843/blog-es-function-d752f225-503e-4602-adec-749d23159d8d"
    s3_object_version = "Zq38oaLaSMwPhBzSChPRIE3Effj3945E"
    memory_size = 128
    role = "${aws_iam_role.IAMRole2.arn}"
    runtime = "nodejs14.x"
    timeout = 3
    tracing_config {
        mode = "PassThrough"
    }
    layers = [
        "arn:aws:lambda:ap-southeast-1:162387011843:layer:Axios-layer:1"
    ]
}

resource "aws_lambda_function" "LambdaFunction2" {
    description = ""
    function_name = "qna-es-function"
    handler = "index.handler"
    architectures = [
        "x86_64"
    ]
    s3_bucket = "awslambda-ap-se-1-tasks"
    s3_key = "/snapshots/162387011843/qna-es-function-98b781e8-1c4f-4f20-b228-d8b7aa981bc0"
    s3_object_version = "Lb2I8lTnMF8gwv1KWhdgj2esBfa3OKNr"
    memory_size = 128
    role = "${aws_iam_role.IAMRole9.arn}"
    runtime = "nodejs14.x"
    timeout = 3
    tracing_config {
        mode = "PassThrough"
    }
}

resource "aws_lambda_layer_version" "LambdaLayerVersion" {
    description = "Lambda layer for http calls"
    compatible_runtimes = [
        "nodejs14.x"
    ]
    license_info = "EdTech"
    layer_name = "Axios-layer"
    s3_bucket = "awslambda-ap-se-1-layers"
    s3_key = "/snapshots/162387011843/Axios-layer-9894454f-4947-49f3-8733-20f94e6b9cef"
}

resource "aws_lambda_event_source_mapping" "LambdaEventSourceMapping" {
    batch_size = 1
    event_source_arn = "arn:aws:dynamodb:ap-southeast-1:162387011843:table/Blogs/stream/2021-10-11T14:15:37.077"
    function_name = "${aws_lambda_function.LambdaFunction.arn}"
    enabled = true
}

resource "aws_s3_bucket" "S3Bucket" {
    bucket = "edtech.k8s.local-state-store"
}

resource "aws_s3_bucket" "S3Bucket2" {
    bucket = "cf-templates-1p791ak2v0e1u-ap-southeast-1"
}

resource "aws_s3_bucket" "S3Bucket3" {
    bucket = "config-bucket-162387011843"
}

resource "aws_s3_bucket" "S3Bucket4" {
    bucket = "edtechfrontend"
}

resource "aws_s3_bucket" "S3Bucket5" {
    bucket = "monitoring-lambda-report"
}

resource "aws_s3_bucket" "S3Bucket6" {
    bucket = "vpc-k8s-flow-log"
}

resource "aws_s3_bucket_policy" "S3BucketPolicy" {
    bucket = "config-bucket-162387011843"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSConfigBucketPermissionsCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::config-bucket-162387011843\"},{\"Sid\":\"AWSConfigBucketExistenceCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"s3:ListBucket\",\"Resource\":\"arn:aws:s3:::config-bucket-162387011843\"},{\"Sid\":\"AWSConfigBucketDelivery\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"config.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::config-bucket-162387011843/AWSLogs/162387011843/Config/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"
}

resource "aws_s3_bucket_policy" "S3BucketPolicy2" {
    bucket = "edtechfrontend"
    policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AddCannedAcl\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::edtechfrontend/*\"}]}"
}

resource "aws_s3_bucket_policy" "S3BucketPolicy3" {
    bucket = "vpc-k8s-flow-log"
    policy = "{\"Version\":\"2012-10-17\",\"Id\":\"AWSLogDeliveryWrite20150319\",\"Statement\":[{\"Sid\":\"AWSLogDeliveryWrite\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"delivery.logs.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::vpc-k8s-flow-log/AWSLogs/162387011843/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"aws:SourceAccount\":\"162387011843\"},\"ArnLike\":{\"aws:SourceArn\":\"arn:aws:logs:ap-southeast-1:162387011843:*\"}}},{\"Sid\":\"AWSLogDeliveryAclCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"delivery.logs.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::vpc-k8s-flow-log\",\"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"162387011843\"},\"ArnLike\":{\"aws:SourceArn\":\"arn:aws:logs:ap-southeast-1:162387011843:*\"}}}]}"
}

resource "aws_rds_cluster" "RDSDBCluster" {
    availability_zones = [
        "ap-southeast-1c",
        "ap-southeast-1a",
        "ap-southeast-1b"
    ]
    backup_retention_period = 1
    database_name = "usr_mgmt"
    cluster_identifier = "usr-mgmt"
    db_cluster_parameter_group_name = "default.aurora-mysql5.7"
    db_subnet_group_name = "default-vpc-b52ffed3"
    engine = "aurora-mysql"
    port = 3306
    master_username = "admin"
    master_password = "REPLACEME"
    preferred_backup_window = "17:08-17:38"
    preferred_maintenance_window = "mon:18:39-mon:19:09"
    vpc_security_group_ids = [
        "${aws_security_group.EC2SecurityGroup15.id}"
    ]
    storage_encrypted = true
    kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/fc44f26b-6be1-4226-8978-3fccd0000412"
    engine_version = "5.7.mysql_aurora.2.07.2"
    iam_database_authentication_enabled = false
    engine_mode = "provisioned"
    deletion_protection = false
}

resource "aws_rds_cluster_instance" "RDSDBInstance" {
    identifier = "usr-mgmt-instance-1"
    instance_class = "db.t2.small"
    engine = "aurora-mysql"
    name = "usr_mgmt"
    preferred_backup_window = "17:08-17:38"
    availability_zone = "ap-southeast-1a"
    preferred_maintenance_window = "fri:16:06-fri:16:36"
    engine_version = "5.7.mysql_aurora.2.07.2"
    auto_minor_version_upgrade = true
    publicly_accessible = true
    port = 3306
    cluster_identifier = "usr-mgmt"
    kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/fc44f26b-6be1-4226-8978-3fccd0000412"
    monitoring_interval = 60
    db_subnet_group_name = "default-vpc-b52ffed3"
}

resource "aws_db_subnet_group" "RDSDBSubnetGroup" {
    description = "Created from the RDS Management Console"
    name = "default-vpc-b52ffed3"
    subnet_ids = [
        "subnet-ba3545e3",
        "subnet-fb80059d",
        "subnet-cbf54083"
    ]
}

resource "aws_opsworks_user_profile" "OpsWorksUserProfile" {
    allow_self_management = false
    user_arn = "arn:aws:iam::162387011843:user/Cloudformation"
    ssh_username = "cloudformation"
}

resource "aws_sns_topic" "SNSTopic" {
    display_name = ""
    name = "Default_CloudWatch_Alarms_Topic"
}

resource "aws_sns_topic_policy" "SNSTopicPolicy" {
    policy = "{\"Version\":\"2008-10-17\",\"Id\":\"__default_policy_ID\",\"Statement\":[{\"Sid\":\"__default_statement_ID\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":[\"SNS:GetTopicAttributes\",\"SNS:SetTopicAttributes\",\"SNS:AddPermission\",\"SNS:RemovePermission\",\"SNS:DeleteTopic\",\"SNS:Subscribe\",\"SNS:ListSubscriptionsByTopic\",\"SNS:Publish\",\"SNS:Receive\"],\"Resource\":\"arn:aws:sns:ap-southeast-1:162387011843:Default_CloudWatch_Alarms_Topic\",\"Condition\":{\"StringEquals\":{\"AWS:SourceOwner\":\"162387011843\"}}}]}"
    arn = "arn:aws:sns:ap-southeast-1:162387011843:Default_CloudWatch_Alarms_Topic"
}

resource "aws_sqs_queue" "SQSQueue" {
    delay_seconds = "0"
    max_message_size = "262144"
    message_retention_seconds = "345600"
    receive_wait_time_seconds = "0"
    visibility_timeout_seconds = "30"
    name = "BlogsQueue"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm" {
    alarm_name = "CPU utilization is above 70%"
    actions_enabled = true
    alarm_actions = [
        "arn:aws:sns:ap-southeast-1:162387011843:Default_CloudWatch_Alarms_Topic"
    ]
    dimensions {}
    evaluation_periods = 5
    datapoints_to_alarm = 3
    comparison_operator = "LessThanLowerOrGreaterThanUpperThreshold"
    treat_missing_data = "missing"
    metric_query {
        id = "m1"
        metric {
            Metric {
                Namespace = "AWS/EC2"
                MetricName = "CPUUtilization"
                Dimensions = [
                    {
                        Name = "InstanceId"
                        Value = "i-0f94d53b470d0ee30"
                    }
                ]
            }
            Period = 300
            Stat = "Average"
        }
        return_data = true
    }
    metric_query {
        expression = "ANOMALY_DETECTION_BAND(m1, 25)"
        id = "ad1"
        label = "CPUUtilization (expected)"
        return_data = true
    }
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm2" {
    alarm_name = "TargetTracking-table/Blogs-AlarmHigh-5979a3bb-fe5b-40d7-9970-bd69052c2e27"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd"
    ]
    metric_name = "ConsumedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Blogs"
    }
    period = 60
    evaluation_periods = 2
    threshold = 42
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm3" {
    alarm_name = "TargetTracking-table/Blogs-AlarmHigh-f7f8bf26-d030-480c-a89a-f96c20091e10"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075"
    ]
    metric_name = "ConsumedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Blogs"
    }
    period = 60
    evaluation_periods = 2
    threshold = 42
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm4" {
    alarm_name = "TargetTracking-table/Blogs-AlarmLow-1c8f089b-9c3c-455b-b10d-1588bd71ed93"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd"
    ]
    metric_name = "ConsumedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Blogs"
    }
    period = 60
    evaluation_periods = 15
    threshold = 30
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm5" {
    alarm_name = "TargetTracking-table/Blogs-AlarmLow-57102431-cf25-4c37-9248-340562532c91"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075"
    ]
    metric_name = "ConsumedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Blogs"
    }
    period = 60
    evaluation_periods = 15
    threshold = 30
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm6" {
    alarm_name = "TargetTracking-table/Blogs-ProvisionedCapacityHigh-38c3ffd4-3924-4c33-a750-c13f237ecf7f"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075"
    ]
    metric_name = "ProvisionedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Blogs"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm7" {
    alarm_name = "TargetTracking-table/Blogs-ProvisionedCapacityHigh-e3e9e4a0-925c-417b-b6c2-bd112ac46294"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd"
    ]
    metric_name = "ProvisionedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Blogs"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm8" {
    alarm_name = "TargetTracking-table/Blogs-ProvisionedCapacityLow-54d4c4e4-3e30-4e09-b3d2-855a67705853"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:ba69582d-98d9-4f70-8383-9790778f481d:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/b08cecaf-7055-439c-aab6-d3aa33d37075"
    ]
    metric_name = "ProvisionedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Blogs"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm9" {
    alarm_name = "TargetTracking-table/Blogs-ProvisionedCapacityLow-b9461768-0175-431a-8894-ae5459ba974a"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:997767cf-25c6-4baf-b313-ea1416e8c6dd:resource/dynamodb/table/Blogs:policyName/$Blogs-scaling-policy:createdBy/0fb4fc00-c532-465e-b294-84bc5d30c0dd"
    ]
    metric_name = "ProvisionedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Blogs"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm10" {
    alarm_name = "TargetTracking-table/Interactions-AlarmHigh-34f79646-0206-4b3e-9a1c-e307b490e58d"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa"
    ]
    metric_name = "ConsumedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Interactions"
    }
    period = 60
    evaluation_periods = 2
    threshold = 42
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm11" {
    alarm_name = "TargetTracking-table/Interactions-AlarmHigh-aeb00ba8-39a5-4376-be79-60f34a36221a"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714"
    ]
    metric_name = "ConsumedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Interactions"
    }
    period = 60
    evaluation_periods = 2
    threshold = 42
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm12" {
    alarm_name = "TargetTracking-table/Interactions-AlarmLow-46b08e3f-9d8b-4dde-9320-5f7f5cc52da5"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714"
    ]
    metric_name = "ConsumedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Interactions"
    }
    period = 60
    evaluation_periods = 15
    threshold = 30
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm13" {
    alarm_name = "TargetTracking-table/Interactions-AlarmLow-9260aea4-d8ee-4def-87cf-da881c2d4177"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa"
    ]
    metric_name = "ConsumedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "Interactions"
    }
    period = 60
    evaluation_periods = 15
    threshold = 30
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm14" {
    alarm_name = "TargetTracking-table/Interactions-ProvisionedCapacityHigh-2bc11770-e36f-4800-8bf7-350c9c8130af"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714"
    ]
    metric_name = "ProvisionedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Interactions"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm15" {
    alarm_name = "TargetTracking-table/Interactions-ProvisionedCapacityHigh-79da493c-7f55-468e-a87c-5269c24265a4"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa"
    ]
    metric_name = "ProvisionedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Interactions"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm16" {
    alarm_name = "TargetTracking-table/Interactions-ProvisionedCapacityLow-c7d55849-e2a0-4160-a47a-f5c974ad57a9"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:780c5189-4151-4e0c-8498-620ef8133d8d:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/ceb3cc55-efd3-4582-9c59-26d0f5beb0fa"
    ]
    metric_name = "ProvisionedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Interactions"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm17" {
    alarm_name = "TargetTracking-table/Interactions-ProvisionedCapacityLow-e8d0af3a-4984-4a1c-97af-9efee9044292"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:5e9311f4-5273-445f-ba50-f89a967fad14:resource/dynamodb/table/Interactions:policyName/$Interactions-scaling-policy:createdBy/7c25befc-ba4a-43af-a212-e738bf726714"
    ]
    metric_name = "ProvisionedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "Interactions"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm18" {
    alarm_name = "TargetTracking-table/QAService-AlarmHigh-67517cf7-7146-46db-8f53-fdd893d97942"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2"
    ]
    metric_name = "ConsumedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "QAService"
    }
    period = 60
    evaluation_periods = 2
    threshold = 42
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm19" {
    alarm_name = "TargetTracking-table/QAService-AlarmHigh-739d9ace-6cc8-4bb6-bac7-81908e646da7"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd"
    ]
    metric_name = "ConsumedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "QAService"
    }
    period = 60
    evaluation_periods = 2
    threshold = 42
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm20" {
    alarm_name = "TargetTracking-table/QAService-AlarmLow-000f5618-689f-4c31-81e8-21bc2b547123"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2"
    ]
    metric_name = "ConsumedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "QAService"
    }
    period = 60
    evaluation_periods = 15
    threshold = 30
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm21" {
    alarm_name = "TargetTracking-table/QAService-AlarmLow-f8511bad-181e-43d0-b015-a64a7e8072b3"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd"
    ]
    metric_name = "ConsumedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Sum"
    dimensions {
        TableName = "QAService"
    }
    period = 60
    evaluation_periods = 15
    threshold = 30
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm22" {
    alarm_name = "TargetTracking-table/QAService-ProvisionedCapacityHigh-02e69722-2bbd-493e-a95d-d1874ed19b69"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2"
    ]
    metric_name = "ProvisionedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "QAService"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm23" {
    alarm_name = "TargetTracking-table/QAService-ProvisionedCapacityHigh-75902844-247c-4433-811e-37b18c65a2d3"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd"
    ]
    metric_name = "ProvisionedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "QAService"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "GreaterThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm24" {
    alarm_name = "TargetTracking-table/QAService-ProvisionedCapacityLow-664b7893-6990-4908-8d94-a2354d21f114"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:81c6e238-c04b-421e-acd2-69c6931e2dc4:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/8259ea7d-bb0c-40f0-a934-bd2d6833a8dd"
    ]
    metric_name = "ProvisionedReadCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "QAService"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_metric_alarm" "CloudWatchAlarm25" {
    alarm_name = "TargetTracking-table/QAService-ProvisionedCapacityLow-bf9be679-c5b1-44d9-89f8-1c79ea864fea"
    alarm_description = "DO NOT EDIT OR DELETE. For TargetTrackingScaling policy arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2."
    actions_enabled = true
    alarm_actions = [
        "arn:aws:autoscaling:ap-southeast-1:162387011843:scalingPolicy:43d54b8a-fb0f-49f1-94af-3ca9ae5b7ce8:resource/dynamodb/table/QAService:policyName/$QAService-scaling-policy:createdBy/9c0b4eba-4ec3-4fab-b324-6bc5c9e126f2"
    ]
    metric_name = "ProvisionedWriteCapacityUnits"
    namespace = "AWS/DynamoDB"
    statistic = "Average"
    dimensions {
        TableName = "QAService"
    }
    period = 300
    evaluation_periods = 3
    threshold = 1
    comparison_operator = "LessThanThreshold"
}

resource "aws_cloudwatch_dashboard" "CloudWatchDashboard" {
    dashboard_name = "EdTech_DynamoDB_Dashboard"
    dashboard_body = "{\"widgets\":[{\"type\":\"metric\",\"x\":0,\"y\":0,\"width\":24,\"height\":6,\"properties\":{\"metrics\":[[\"AWS/DynamoDB\",\"AccountMaxReads\",{\"visible\":false}],[\".\",\"AccountProvisionedReadCapacityUtilization\",{\"visible\":false}],[\".\",\"UserErrors\",{\"visible\":false}],[\".\",\"ConsumedWriteCapacityUnits\",\"TableName\",\"Blogs\"],[\".\",\"ProvisionedWriteCapacityUnits\",\".\",\".\"],[\".\",\"ProvisionedReadCapacityUnits\",\".\",\".\"],[\".\",\"ConsumedReadCapacityUnits\",\".\",\".\"],[\".\",\"ProvisionedReadCapacityUnits\",\".\",\"Interactions\"],[\".\",\"ProvisionedWriteCapacityUnits\",\".\",\".\"],[\".\",\"ConsumedReadCapacityUnits\",\".\",\".\"],[\".\",\"ConsumedWriteCapacityUnits\",\".\",\".\"],[\"...\",\"QAService\"],[\".\",\"ProvisionedWriteCapacityUnits\",\".\",\".\"],[\".\",\"ProvisionedReadCapacityUnits\",\".\",\".\"],[\".\",\"ConsumedReadCapacityUnits\",\".\",\".\"]],\"view\":\"singleValue\",\"stacked\":false,\"region\":\"ap-southeast-1\",\"stat\":\"Average\",\"period\":300,\"title\":\"Table Metrics\"}},{\"type\":\"metric\",\"x\":0,\"y\":6,\"width\":24,\"height\":3,\"properties\":{\"view\":\"timeSeries\",\"stacked\":true,\"metrics\":[[\"AWS/DynamoDB\",\"SuccessfulRequestLatency\",\"TableName\",\"Blogs\",\"Operation\",\"GetItem\"],[\"...\",\"Interactions\",\".\",\".\"],[\"...\",\"QAService\",\".\",\".\"],[\"...\",\"TryDaxTable\",\".\",\".\"]],\"region\":\"ap-southeast-1\",\"title\":\"Get Call Response Time\"}},{\"type\":\"metric\",\"x\":0,\"y\":9,\"width\":24,\"height\":3,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/DynamoDB\",\"ReturnedItemCount\",\"TableName\",\"TryDaxTable\",\"Operation\",\"Scan\"],[\"...\",\"Query\"],[\"...\",\"QAService\",\".\",\"Scan\"],[\"...\",\"Interactions\",\".\",\".\"],[\"...\",\"Blogs\",\".\",\".\"]],\"region\":\"ap-southeast-1\",\"title\":\"Request Count\"}}]}"
}

resource "aws_cloudwatch_dashboard" "CloudWatchDashboard2" {
    dashboard_name = "EdTech_S3_Dashboard"
    dashboard_body = "{\"widgets\":[{\"type\":\"metric\",\"x\":0,\"y\":0,\"width\":24,\"height\":6,\"properties\":{\"view\":\"timeSeries\",\"metrics\":[[\"AWS/S3\",\"NumberOfObjects\",\"StorageType\",\"AllStorageTypes\",\"BucketName\",\"cf-templates-1p791ak2v0e1u-ap-southeast-1\",{\"period\":86400}],[\"...\",\"edtech.k8s.local-state-store\",{\"period\":86400}],[\"...\",\"edtechfrontend\",{\"period\":86400}],[\"...\",\"monitoring-lambda-report\",{\"period\":86400}]],\"region\":\"ap-southeast-1\",\"stacked\":false,\"title\":\"S3 bucket numnber of objects\"}},{\"type\":\"metric\",\"x\":0,\"y\":6,\"width\":24,\"height\":6,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/S3\",\"BucketSizeBytes\",\"StorageType\",\"StandardStorage\",\"BucketName\",\"cf-templates-1p791ak2v0e1u-ap-southeast-1\",{\"period\":86400}],[\"...\",\"edtech.k8s.local-state-store\",{\"period\":86400}],[\"...\",\"edtechfrontend\",{\"period\":86400}],[\"...\",\"monitoring-lambda-report\",{\"period\":86400}]],\"region\":\"ap-southeast-1\",\"title\":\"S3 bucket size\"}},{\"type\":\"metric\",\"x\":0,\"y\":12,\"width\":24,\"height\":3,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/Usage\",\"CallCount\",\"Type\",\"API\",\"Resource\",\"GetBucketLogging\",\"Service\",\"S3\",\"Class\",\"None\"],[\"...\",\"GetBucketWebsite\",\".\",\".\",\".\",\".\"],[\"...\",\"PutBucketWebsite\",\".\",\".\",\".\",\".\"]],\"region\":\"ap-southeast-1\",\"title\":\"S3 bucket usage\"}}]}"
}

resource "aws_cloudwatch_dashboard" "CloudWatchDashboard3" {
    dashboard_name = "EdTech_ElasticSearch_Dashboard"
    dashboard_body = "{\"widgets\":[{\"type\":\"metric\",\"x\":0,\"y\":0,\"width\":6,\"height\":6,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/ES\",\"MasterCPUUtilization\",\"DomainName\",\"blog-elasticsearch\",\"NodeId\",\"EN9YrEsuTpuOGHy3UMnPRg\",\"ClientId\",\"162387011843\"],[\"...\",\"9G04ePfAQ_GZ82k-cj5GAA\",\".\",\".\"],[\"...\",\"x_pvPx8lS7qnNfHlOWPtDA\",\".\",\".\"]],\"region\":\"ap-southeast-1\",\"title\":\"CPU utilization per node\"}},{\"type\":\"metric\",\"x\":6,\"y\":0,\"width\":6,\"height\":6,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/ES\",\"MasterCPUUtilization\",\"DomainName\",\"blog-elasticsearch\",\"ClientId\",\"162387011843\"]],\"region\":\"ap-southeast-1\",\"title\":\"CPU Utilization per domain\"}},{\"type\":\"metric\",\"x\":0,\"y\":6,\"width\":24,\"height\":3,\"properties\":{\"view\":\"singleValue\",\"stacked\":false,\"metrics\":[[\"AWS/ES\",\"ADExecuteFailureCount\",\"DomainName\",\"blog-elasticsearch\",\"ClientId\",\"162387011843\"],[\".\",\"FreeStorageSpace\",\".\",\".\",\".\",\".\"],[\".\",\"OpenSearchRequests\",\".\",\".\",\".\",\".\"]],\"region\":\"ap-southeast-1\",\"title\":\"Stats\"}}]}"
}

resource "aws_cloudwatch_dashboard" "CloudWatchDashboard4" {
    dashboard_name = "EdTech_EC2_Dashboard"
    dashboard_body = "{\"widgets\":[{\"type\":\"metric\",\"x\":0,\"y\":0,\"width\":12,\"height\":6,\"properties\":{\"metrics\":[[\"AWS/EC2\",\"CPUUtilization\",\"AutoScalingGroupName\",\"master-ap-southeast-1a.masters.edtech.k8s.local\",{\"visible\":false}],[\".\",\"CPUCreditUsage\",\".\",\".\",{\"visible\":false}],[\".\",\"CPUSurplusCreditBalance\",\".\",\".\",{\"visible\":false}],[\".\",\"CPUCreditBalance\",\".\",\".\",{\"visible\":false}],[\".\",\"CPUUtilization\",\"InstanceId\",\"i-0d8ffdcaf6bcc4701\"],[\"...\",\"i-098c0d44a89ca86f6\"],[\"...\",\"i-06b4ad361ba0bdf85\"],[\"...\",\"i-0f94d53b470d0ee30\"]],\"view\":\"timeSeries\",\"region\":\"ap-southeast-1\",\"stacked\":false,\"stat\":\"Average\",\"period\":300,\"title\":\"CPU utilization \"}},{\"type\":\"metric\",\"x\":12,\"y\":0,\"width\":12,\"height\":6,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/EC2\",\"NetworkOut\",\"InstanceId\",\"i-0d8ffdcaf6bcc4701\"],[\"...\",\"i-098c0d44a89ca86f6\"],[\"...\",\"i-06b4ad361ba0bdf85\"],[\"...\",\"i-0f94d53b470d0ee30\"]],\"region\":\"ap-southeast-1\",\"title\":\"Network Outbond data\"}},{\"type\":\"metric\",\"x\":0,\"y\":6,\"width\":6,\"height\":6,\"properties\":{\"view\":\"timeSeries\",\"stacked\":false,\"metrics\":[[\"AWS/EC2\",\"StatusCheckFailed_System\",\"InstanceId\",\"i-0d8ffdcaf6bcc4701\"],[\"...\",\"i-098c0d44a89ca86f6\"],[\"...\",\"i-06b4ad361ba0bdf85\"],[\"...\",\"i-0f94d53b470d0ee30\"]],\"region\":\"ap-southeast-1\",\"title\":\"Status check fail\"}}]}"
}

resource "aws_cloudwatch_log_group" "LogsLogGroup" {
    name = "/aws/lambda/blog-es-function"
}

resource "aws_cloudwatch_log_group" "LogsLogGroup2" {
    name = "/ecs/ecsconsole-helloworld"
}

resource "aws_cloudwatch_log_group" "LogsLogGroup3" {
    name = "RDSOSMetrics"
    retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "LogsLogGroup4" {
    name = "application_logs"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]0e0c16a222404e058a967f642c31cef9"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream2" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]5227251d1a364acbac063b3c4329009f"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream3" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]70d9e64b09b948e9a10c9d6096548218"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream4" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]71a8f0b4ca564c9586d24f3468eff368"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream5" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]7b28d37691b146e9bea00cadd6038574"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream6" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]a241049876454fd799e77ca324ec98d3"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream7" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]ad5991c0a744433c860c21d55d3fbf48"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream8" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]b723971136ca42a8a6a89e7222d64e79"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream9" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]c5bcb3c248124a489de4cf9f15a38109"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream10" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]c7fd8cd8403a46c0b3caf9fe084019d4"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream11" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]c9204f82b0854bbc8c9e3e21f2de0679"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream12" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/11/[$LATEST]dd89661fa6004a26802805bb69f10e36"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream13" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]05af926d7d5c4c43a8edc5694e113c45"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream14" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]0aad1040f5aa40b88cdf824bd12ad298"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream15" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]105c22cf218b490090db9d4c3763c7d2"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream16" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]1139c3f690ca41bfbdedb0213c5fcb63"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream17" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]1fd4e6be58e040b09136602363d44ead"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream18" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]3ccf565696144c538e22ea28051c690a"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream19" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]3fe45c2269694c2e9c9e5b769a6c6466"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream20" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]757ed5c0e1c44761b6944b4ff2479d4b"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream21" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]87da312d50cf4d0db54f5dbc2dbbec3a"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream22" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]96645424dd5d4406b27dfadcddf240b9"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream23" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/12/[$LATEST]ef929720bea14b49b853770879dac333"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream24" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]0ad31d919c2c473b8f76260b8fb9b912"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream25" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]19b94ae4e918462189bb3541e5697035"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream26" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]33dfafd07a88447f987b53b3adf8c714"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream27" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]4153ca8f25294c3e8fe8c315201b4343"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream28" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]5636a664269246d3aae9f4e80db895c5"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream29" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]5a102d39778e41768e2dcf57f48ee05d"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream30" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]7471b8fdd03f4978abc7d526e1352b04"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream31" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]d050296f0b7544b99901db147f1295fb"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream32" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]e70f8a1563ed44b5b6ae0c941579b607"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream33" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/13/[$LATEST]ed0ecab622bc4d40af8215d1808c3ac7"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream34" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/15/[$LATEST]1e7c34ca2b254f038ec2e5debceea16a"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream35" {
    log_group_name = "/aws/lambda/blog-es-function"
    name = "2021/10/15/[$LATEST]76d17f0749ec4f43a6f7d1a6f9975b93"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream36" {
    log_group_name = "/ecs/ecsconsole-helloworld"
    name = "ecs/sample-app/280c8774a1e34b36b5c9d461b6f1cac6"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream37" {
    log_group_name = "/ecs/ecsconsole-helloworld"
    name = "ecs/sample-app/43a03fc41ed94872a3607558ebb2cf9c"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream38" {
    log_group_name = "RDSOSMetrics"
    name = "db-2DNAJY2TRTRJEH37DO3ZIQRT6M"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream39" {
    log_group_name = "RDSOSMetrics"
    name = "db-BFKXE5MGGI4ASELH4RXZOYP3LM"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream40" {
    log_group_name = "RDSOSMetrics"
    name = "db-LNX3VHH6RBAIGUXFUCSYTYK5ZA"
}

resource "aws_cloudwatch_log_stream" "LogsLogStream41" {
    log_group_name = "application_logs"
    name = "i-0d8ffdcaf6bcc4701"
}

resource "aws_cloudwatch_log_metric_filter" "LogsMetricFilter" {
    pattern = "Error"
    log_group_name = "application_logs"
    metric_transformation {
        name = "Error_Metric"
        namespace = "Error messages in log"
        value = "1"
    }
}

resource "aws_dynamodb_table" "DynamoDBTable" {
    attribute {
        name = "blogid"
        type = "S"
    }
    name = "Blogs"
    hash_key = "blogid"
    read_capacity = 1
    write_capacity = 1
    stream_enabled = true
    stream_view_type = "NEW_IMAGE"
    ttl {
        enabled = false
    }
}

resource "aws_dynamodb_table" "DynamoDBTable2" {
    attribute {
        name = "interactionid"
        type = "S"
    }
    name = "Interactions"
    hash_key = "interactionid"
    read_capacity = 1
    write_capacity = 1
    ttl {
        enabled = false
    }
}

resource "aws_dynamodb_table" "DynamoDBTable3" {
    attribute {
        name = "questionId"
        type = "S"
    }
    name = "QAService"
    hash_key = "questionId"
    read_capacity = 1
    write_capacity = 1
    ttl {
        enabled = false
    }
}

resource "aws_dax_cluster" "DAXCluster" {
    cluster_name = "mydaxcluster"
    node_type = "dax.t3.small"
    maintenance_window = "tue:15:00-tue:16:00"
    subnet_group_name = "myk8s-subnet-group"
    security_group_ids = [
        "${aws_security_group.EC2SecurityGroup8.id}"
    ]
    iam_role_arn = "${aws_iam_role.IAMRole.arn}"
    parameter_group_name = "default.dax1.0"
    server_side_encryption {
        enabled = true
    }
    availability_zones  = [
        "ap-southeast-1a",
        "ap-southeast-1b"
    ]
}

resource "aws_dax_subnet_group" "DAXSubnetGroup" {
    name = "myk8s-subnet-group"
    subnet_ids = [
        "subnet-073aadc3871ef404e",
        "subnet-052966279351b9b08"
    ]
}

resource "aws_ecr_repository" "ECRRepository" {
    name = "gamification-service"
}

resource "aws_ecr_repository" "ECRRepository2" {
    name = "blogs-elasticsearch-repo"
}

resource "aws_ecr_repository" "ECRRepository3" {
    name = "react-ecr-repo"
}

resource "aws_ecr_repository" "ECRRepository4" {
    name = "qaservice-repo"
}

resource "aws_ecr_repository" "ECRRepository5" {
    name = "qna-elasticsearch-repo"
}

resource "aws_ecr_repository" "ECRRepository6" {
    name = "interactions-service-repo"
}

resource "aws_ecr_repository" "ECRRepository7" {
    name = "usrmgmt-service"
}

resource "aws_ecr_repository" "ECRRepository8" {
    name = "testecr"
}

resource "aws_ecr_repository" "ECRRepository9" {
    name = "blogs-service-repo"
}

resource "aws_ecs_task_definition" "ECSTaskDefinition" {
    container_definitions = "[{\"name\":\"sample-app\",\"image\":\"httpd:2.4\",\"cpu\":256,\"memoryReservation\":512,\"links\":[],\"portMappings\":[{\"containerPort\":80,\"hostPort\":80,\"protocol\":\"tcp\"}],\"essential\":true,\"entryPoint\":[\"sh\",\"-c\"],\"command\":[\"/bin/sh -c \\\"echo '<html> <head> <title>Amazon ECS Sample App</title> <style>body {margin-top: 40px; background-color: #333;} </style> </head><body> <div style=color:white;text-align:center> <h1>Amazon ECS Sample App</h1> <h2>Congratulations!</h2> <p>Your application is now running on a container in Amazon ECS.</p> </div></body></html>' >  /usr/local/apache2/htdocs/index.html && httpd-foreground\\\"\"],\"environment\":[],\"mountPoints\":[],\"volumesFrom\":[],\"logConfiguration\":{\"logDriver\":\"awslogs\",\"options\":{\"awslogs-group\":\"/ecs/ecsconsole-helloworld\",\"awslogs-region\":\"ap-southeast-1\",\"awslogs-stream-prefix\":\"ecs\"}}}]"
    family = "ecsconsole-helloworld"
    execution_role_arn = "${aws_iam_role.IAMRole5.arn}"
    network_mode = "awsvpc"
    requires_compatibilities = [
        "FARGATE"
    ]
    cpu = "256"
    memory = "512"
}

resource "aws_api_gateway_rest_api" "ApiGatewayRestApi" {
    name = "Gamification API"
    description = "ASP.NET Core Web API for gamification for Blogs data"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
}

resource "aws_api_gateway_rest_api" "ApiGatewayRestApi2" {
    name = "blog-api"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
}

resource "aws_api_gateway_rest_api" "ApiGatewayRestApi3" {
    name = "EcsDemoAPI"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
}

resource "aws_api_gateway_rest_api" "ApiGatewayRestApi4" {
    name = "User Management API"
    description = "ASP.NET Core Web API for storing and mofiying user data"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
}

resource "aws_api_gateway_rest_api" "ApiGatewayRestApi5" {
    name = "ElasticSearch API for Blogs"
    description = "ASP.NET Core Web API for transactions of elasticsearch for Blogs data"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
}

resource "aws_api_gateway_rest_api" "ApiGatewayRestApi6" {
    name = "interaction-api"
    description = "reverse proxy for connection to interaction-api-service"
    api_key_source = "HEADER"
    endpoint_configuration {
        types = [
            "REGIONAL"
        ]
    }
}

resource "aws_api_gateway_stage" "ApiGatewayStage" {
    stage_name = "dev"
    deployment_id = "e1ond6"
    rest_api_id = "7cgsd87dq2"
    cache_cluster_enabled = false
    cache_cluster_size = "0.5"
    variables {
        helloworldElb = "https://7cgsd87dq2.execute-api.ap-southeast-1.amazonaws.com/dev"
    }
    xray_tracing_enabled = false
}

resource "aws_api_gateway_stage" "ApiGatewayStage2" {
    stage_name = "prod"
    deployment_id = "lw8dwd"
    rest_api_id = "23uh31eppf"
    description = "production"
    cache_cluster_enabled = false
    xray_tracing_enabled = false
}

resource "aws_api_gateway_stage" "ApiGatewayStage3" {
    stage_name = "prod"
    deployment_id = "diic2j"
    rest_api_id = "hyaejq58a6"
    description = "Production"
    cache_cluster_enabled = false
    xray_tracing_enabled = false
}

resource "aws_api_gateway_stage" "ApiGatewayStage4" {
    stage_name = "prod"
    deployment_id = "evq19y"
    rest_api_id = "uxcgv1dtci"
    description = "production"
    cache_cluster_enabled = false
    xray_tracing_enabled = false
}

resource "aws_api_gateway_stage" "ApiGatewayStage5" {
    stage_name = "prod"
    deployment_id = "rz5r5u"
    rest_api_id = "vj7n2vxl65"
    description = "production"
    cache_cluster_enabled = false
    xray_tracing_enabled = false
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment" {
    rest_api_id = "23uh31eppf"
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment2" {
    rest_api_id = "7cgsd87dq2"
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment3" {
    rest_api_id = "hyaejq58a6"
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment4" {
    rest_api_id = "qkdd1qkf4h"
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment5" {
    rest_api_id = "qkdd1qkf4h"
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment6" {
    rest_api_id = "uxcgv1dtci"
}

resource "aws_api_gateway_deployment" "ApiGatewayDeployment7" {
    rest_api_id = "vj7n2vxl65"
}

resource "aws_api_gateway_resource" "ApiGatewayResource" {
    rest_api_id = "23uh31eppf"
    path_part = "v1"
    parent_id = "xdoxbc"
}

resource "aws_api_gateway_resource" "ApiGatewayResource2" {
    rest_api_id = "23uh31eppf"
    path_part = "Gamification"
    parent_id = "h99y2x"
}

resource "aws_api_gateway_resource" "ApiGatewayResource3" {
    rest_api_id = "23uh31eppf"
    path_part = "api"
    parent_id = "uy4h41ps3c"
}

resource "aws_api_gateway_resource" "ApiGatewayResource4" {
    rest_api_id = "hyaejq58a6"
    path_part = "v1"
    parent_id = "fbdytj"
}

resource "aws_api_gateway_resource" "ApiGatewayResource5" {
    rest_api_id = "hyaejq58a6"
    path_part = "BadgeMgmt"
    parent_id = "5ve8pn"
}

resource "aws_api_gateway_resource" "ApiGatewayResource6" {
    rest_api_id = "hyaejq58a6"
    path_part = "UserMgmt"
    parent_id = "5ve8pn"
}

resource "aws_api_gateway_resource" "ApiGatewayResource7" {
    rest_api_id = "hyaejq58a6"
    path_part = "api"
    parent_id = "hs32uaz48b"
}

resource "aws_api_gateway_resource" "ApiGatewayResource8" {
    rest_api_id = "vj7n2vxl65"
    path_part = "autoComplete"
    parent_id = "3ve5n3"
}

resource "aws_api_gateway_resource" "ApiGatewayResource9" {
    rest_api_id = "vj7n2vxl65"
    path_part = "BlogElasticSearch"
    parent_id = "wtz2kd"
}

resource "aws_api_gateway_resource" "ApiGatewayResource10" {
    rest_api_id = "vj7n2vxl65"
    path_part = "search"
    parent_id = "3ve5n3"
}

resource "aws_api_gateway_resource" "ApiGatewayResource11" {
    rest_api_id = "vj7n2vxl65"
    path_part = "{text}"
    parent_id = "j5caho"
}

resource "aws_api_gateway_resource" "ApiGatewayResource12" {
    rest_api_id = "vj7n2vxl65"
    path_part = "v1"
    parent_id = "ykzwqy"
}

resource "aws_api_gateway_resource" "ApiGatewayResource13" {
    rest_api_id = "vj7n2vxl65"
    path_part = "api"
    parent_id = "65c4hiyyl6"
}

resource "aws_api_gateway_resource" "ApiGatewayResource14" {
    rest_api_id = "uxcgv1dtci"
    path_part = "{seedtype}"
    parent_id = "h7u8xr"
}

resource "aws_api_gateway_resource" "ApiGatewayResource15" {
    rest_api_id = "uxcgv1dtci"
    path_part = "interaction"
    parent_id = "h7u8xr"
}

resource "aws_api_gateway_resource" "ApiGatewayResource16" {
    rest_api_id = "uxcgv1dtci"
    path_part = "author"
    parent_id = "h7u8xr"
}

resource "aws_api_gateway_resource" "ApiGatewayResource17" {
    rest_api_id = "uxcgv1dtci"
    path_part = "interactions"
    parent_id = "ukaqr5"
}

resource "aws_api_gateway_resource" "ApiGatewayResource18" {
    rest_api_id = "uxcgv1dtci"
    path_part = "author"
    parent_id = "53aeoy"
}

resource "aws_api_gateway_resource" "ApiGatewayResource19" {
    rest_api_id = "uxcgv1dtci"
    path_part = "v1"
    parent_id = "izv1hwjuzc"
}

resource "aws_api_gateway_resource" "ApiGatewayResource20" {
    rest_api_id = "23uh31eppf"
    path_part = "updateBadgeAndTrophy"
    parent_id = "iuy0v3"
}

resource "aws_api_gateway_resource" "ApiGatewayResource21" {
    rest_api_id = "hyaejq58a6"
    path_part = "modifyBadge"
    parent_id = "681tsa"
}

resource "aws_api_gateway_resource" "ApiGatewayResource22" {
    rest_api_id = "hyaejq58a6"
    path_part = "modifyProfile"
    parent_id = "acuhmt"
}

resource "aws_api_gateway_resource" "ApiGatewayResource23" {
    rest_api_id = "7cgsd87dq2"
    path_part = "helloworld"
    parent_id = "a9l6r6ugye"
}

resource "aws_api_gateway_resource" "ApiGatewayResource24" {
    rest_api_id = "hyaejq58a6"
    path_part = "addProfile"
    parent_id = "acuhmt"
}

resource "aws_api_gateway_resource" "ApiGatewayResource25" {
    rest_api_id = "hyaejq58a6"
    path_part = "getBadgeList"
    parent_id = "681tsa"
}

resource "aws_api_gateway_resource" "ApiGatewayResource26" {
    rest_api_id = "hyaejq58a6"
    path_part = "deleteBadge"
    parent_id = "681tsa"
}

resource "aws_api_gateway_resource" "ApiGatewayResource27" {
    rest_api_id = "hyaejq58a6"
    path_part = "deleteProfile"
    parent_id = "acuhmt"
}

resource "aws_api_gateway_resource" "ApiGatewayResource28" {
    rest_api_id = "hyaejq58a6"
    path_part = "getBadgeListById"
    parent_id = "681tsa"
}

resource "aws_api_gateway_resource" "ApiGatewayResource29" {
    rest_api_id = "hyaejq58a6"
    path_part = "addBadge"
    parent_id = "681tsa"
}

resource "aws_api_gateway_resource" "ApiGatewayResource30" {
    rest_api_id = "hyaejq58a6"
    path_part = "getProfileByUserName"
    parent_id = "acuhmt"
}

resource "aws_api_gateway_resource" "ApiGatewayResource31" {
    rest_api_id = "hyaejq58a6"
    path_part = "getProfileByEmail"
    parent_id = "acuhmt"
}

resource "aws_api_gateway_resource" "ApiGatewayResource32" {
    rest_api_id = "qkdd1qkf4h"
    path_part = "postblog"
    parent_id = "j343tdx6t2"
}

resource "aws_api_gateway_resource" "ApiGatewayResource33" {
    rest_api_id = "qkdd1qkf4h"
    path_part = "allblogs"
    parent_id = "j343tdx6t2"
}

resource "aws_api_gateway_resource" "ApiGatewayResource34" {
    rest_api_id = "qkdd1qkf4h"
    path_part = "getblogbyid"
    parent_id = "j343tdx6t2"
}

resource "aws_api_gateway_resource" "ApiGatewayResource35" {
    rest_api_id = "qkdd1qkf4h"
    path_part = "-blogid-"
    parent_id = "oftxc1"
}

resource "aws_api_gateway_resource" "ApiGatewayResource36" {
    rest_api_id = "vj7n2vxl65"
    path_part = "personalizedFeed"
    parent_id = "3ve5n3"
}

resource "aws_api_gateway_resource" "ApiGatewayResource37" {
    rest_api_id = "uxcgv1dtci"
    path_part = "{seedid}"
    parent_id = "53aeoy"
}

resource "aws_api_gateway_resource" "ApiGatewayResource38" {
    rest_api_id = "vj7n2vxl65"
    path_part = "{text}"
    parent_id = "35f6su"
}

resource "aws_api_gateway_resource" "ApiGatewayResource39" {
    rest_api_id = "vj7n2vxl65"
    path_part = "{page}"
    parent_id = "lutf1a"
}

resource "aws_api_gateway_resource" "ApiGatewayResource40" {
    rest_api_id = "vj7n2vxl65"
    path_part = "trendingBlogTags"
    parent_id = "3ve5n3"
}

resource "aws_api_gateway_resource" "ApiGatewayResource41" {
    rest_api_id = "uxcgv1dtci"
    path_part = "{interactionId}"
    parent_id = "6uy9sn"
}

resource "aws_api_gateway_resource" "ApiGatewayResource42" {
    rest_api_id = "uxcgv1dtci"
    path_part = "all"
    parent_id = "h7u8xr"
}

resource "aws_api_gateway_resource" "ApiGatewayResource43" {
    rest_api_id = "uxcgv1dtci"
    path_part = "{author}"
    parent_id = "hp76ju"
}

resource "aws_api_gateway_resource" "ApiGatewayResource44" {
    rest_api_id = "uxcgv1dtci"
    path_part = "{authorid}"
    parent_id = "a476uc"
}

resource "aws_api_gateway_resource" "ApiGatewayResource45" {
    rest_api_id = "qkdd1qkf4h"
    path_part = "getallblogs"
    parent_id = "j343tdx6t2"
}

resource "aws_api_gateway_method" "ApiGatewayMethod" {
    rest_api_id = "23uh31eppf"
    resource_id = "v4jw2z"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod2" {
    rest_api_id = "hyaejq58a6"
    resource_id = "eryr0a"
    http_method = "PUT"
    authorization = "NONE"
    api_key_required = false
    request_models {
        application/*+json = "Badge"
        application/json = "Badge"
        application/json-patch+json = "Badge"
        text/json = "Badge"
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod3" {
    rest_api_id = "hyaejq58a6"
    resource_id = "4wxtr0"
    http_method = "PUT"
    authorization = "NONE"
    api_key_required = false
    request_models {
        application/*+json = "UserInfo"
        application/json = "UserInfo"
        application/json-patch+json = "UserInfo"
        text/json = "UserInfo"
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod4" {
    rest_api_id = "7cgsd87dq2"
    resource_id = "4dxqgo"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod5" {
    rest_api_id = "hyaejq58a6"
    resource_id = "fylm9y"
    http_method = "POST"
    authorization = "NONE"
    api_key_required = false
    request_models {
        application/*+json = "UserInfo"
        application/json = "UserInfo"
        application/json-patch+json = "UserInfo"
        text/json = "UserInfo"
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod6" {
    rest_api_id = "hyaejq58a6"
    resource_id = "ow4knr"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
}

resource "aws_api_gateway_method" "ApiGatewayMethod7" {
    rest_api_id = "hyaejq58a6"
    resource_id = "p9jv95"
    http_method = "DELETE"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.BadgeName = false
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod8" {
    rest_api_id = "hyaejq58a6"
    resource_id = "l9bwnp"
    http_method = "DELETE"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.emailId = false
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod9" {
    rest_api_id = "hyaejq58a6"
    resource_id = "riwmkb"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.badgeId = false
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod10" {
    rest_api_id = "hyaejq58a6"
    resource_id = "lo4czo"
    http_method = "POST"
    authorization = "NONE"
    api_key_required = false
    request_models {
        application/*+json = "Badge"
        application/json = "Badge"
        application/json-patch+json = "Badge"
        text/json = "Badge"
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod11" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "43paph"
    http_method = "ANY"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod12" {
    rest_api_id = "hyaejq58a6"
    resource_id = "x70e33"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.userName = false
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod13" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "43paph"
    http_method = "OPTIONS"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod14" {
    rest_api_id = "hyaejq58a6"
    resource_id = "q0ah1a"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.emailId = false
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod15" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "byzyk1"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod16" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "43paph"
    http_method = "POST"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.author = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod17" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "byzyk1"
    http_method = "OPTIONS"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod18" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "oftxc1"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod19" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "oftxc1"
    http_method = "OPTIONS"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod20" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "4a36ho"
    http_method = "OPTIONS"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod21" {
    rest_api_id = "vj7n2vxl65"
    resource_id = "olb7e1"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.querystring.text = false
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod22" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "s47snj"
    http_method = "OPTIONS"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod23" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "czgpms"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.seedid = true
        method.request.path.seedtype = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod24" {
    rest_api_id = "vj7n2vxl65"
    resource_id = "ai5n8j"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.text = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod25" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "cp6tnc"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.author = true
        method.request.path.seedtype = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod26" {
    rest_api_id = "vj7n2vxl65"
    resource_id = "sts8nk"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.page = true
        method.request.path.text = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod27" {
    rest_api_id = "vj7n2vxl65"
    resource_id = "th60y5"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
}

resource "aws_api_gateway_method" "ApiGatewayMethod28" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "v9sfih"
    http_method = "DELETE"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.interactionId = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod29" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "v9sfih"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.interactionId = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod30" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "pettir"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_method" "ApiGatewayMethod31" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "cp6tnc"
    http_method = "POST"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.author = true
        method.request.path.seedtype = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod32" {
    rest_api_id = "uxcgv1dtci"
    resource_id = "udxysg"
    http_method = "DELETE"
    authorization = "NONE"
    api_key_required = false
    request_parameters {
        method.request.path.authorid = true
    }
}

resource "aws_api_gateway_method" "ApiGatewayMethod33" {
    rest_api_id = "qkdd1qkf4h"
    resource_id = "s47snj"
    http_method = "GET"
    authorization = "NONE"
    api_key_required = false
    request_parameters {}
}

resource "aws_api_gateway_model" "ApiGatewayModel" {
    rest_api_id = "7cgsd87dq2"
    name = "Error"
    description = "This is a default error schema model"
    schema = <<EOF
{
  "$schema" : "http://json-schema.org/draft-04/schema#",
  "title" : "Error Schema",
  "type" : "object",
  "properties" : {
    "message" : { "type" : "string" }
  }
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel2" {
    rest_api_id = "7cgsd87dq2"
    name = "Empty"
    description = "This is a default empty schema model"
    schema = <<EOF
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title" : "Empty Schema",
  "type" : "object"
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel3" {
    rest_api_id = "qkdd1qkf4h"
    name = "Empty"
    description = "This is a default empty schema model"
    schema = <<EOF
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title" : "Empty Schema",
  "type" : "object"
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel4" {
    rest_api_id = "qkdd1qkf4h"
    name = "Error"
    description = "This is a default error schema model"
    schema = <<EOF
{
  "$schema" : "http://json-schema.org/draft-04/schema#",
  "title" : "Error Schema",
  "type" : "object",
  "properties" : {
    "message" : { "type" : "string" }
  }
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel5" {
    rest_api_id = "hyaejq58a6"
    name = "UserInfo"
    schema = <<EOF
{
  "type" : "object",
  "properties" : {
    "userId" : {
      "type" : "integer",
      "format" : "int32"
    },
    "userEmailId" : {
      "type" : "string"
    },
    "userName" : {
      "type" : "string"
    },
    "age" : {
      "type" : "integer",
      "format" : "int32"
    },
    "phoneNumber" : {
      "type" : "string"
    },
    "badgeIds" : {
      "type" : "string"
    },
    "trophyIds" : {
      "type" : "string"
    },
    "genres" : {
      "type" : "string"
    },
    "inUse" : {
      "type" : "boolean"
    },
    "createTimestamp" : {
      "type" : "string",
      "format" : "date-time"
    },
    "createId" : {
      "type" : "string"
    },
    "updateTimestamp" : {
      "type" : "string",
      "format" : "date-time"
    },
    "updateId" : {
      "type" : "string"
    }
  },
  "additionalProperties" : false
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel6" {
    rest_api_id = "hyaejq58a6"
    name = "Badge"
    schema = <<EOF
{
  "type" : "object",
  "properties" : {
    "badgeId" : {
      "type" : "integer",
      "format" : "int32"
    },
    "badgeName" : {
      "type" : "string"
    },
    "badgeDescription" : {
      "type" : "string"
    },
    "createTimestamp" : {
      "type" : "string",
      "format" : "date-time"
    },
    "createId" : {
      "type" : "string"
    },
    "updateTimestamp" : {
      "type" : "string",
      "format" : "date-time"
    },
    "updateId" : {
      "type" : "string"
    }
  },
  "additionalProperties" : false
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel7" {
    rest_api_id = "uxcgv1dtci"
    name = "Empty"
    description = "This is a default empty schema model"
    schema = <<EOF
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "title" : "Empty Schema",
  "type" : "object"
}
EOF
    content_type = "application/json"
}

resource "aws_api_gateway_model" "ApiGatewayModel8" {
    rest_api_id = "uxcgv1dtci"
    name = "Error"
    description = "This is a default error schema model"
    schema = <<EOF
{
  "$schema" : "http://json-schema.org/draft-04/schema#",
  "title" : "Error Schema",
  "type" : "object",
  "properties" : {
    "message" : { "type" : "string" }
  }
}
EOF
    content_type = "application/json"
}

resource "aws_neptune_subnet_group" "NeptuneDBSubnetGroup" {
    name = "default-vpc-b52ffed3"
    description = "Created from the RDS Management Console"
    subnet_ids = [
        "subnet-ba3545e3",
        "subnet-fb80059d",
        "subnet-cbf54083"
    ]
}

resource "aws_docdb_subnet_group" "DocDBDBSubnetGroup" {
    name = "default-vpc-b52ffed3"
    description = "Created from the RDS Management Console"
    subnet_ids = [
        "subnet-ba3545e3",
        "subnet-fb80059d",
        "subnet-cbf54083"
    ]
}

resource "aws_budgets_budget" "BudgetsBudget" {
    limit_amount = "20.0"
    limit_unit = "USD"
    time_period_end = "2087-06-15T00:00:00.000Z"
    time_period_start = "2021-08-01T00:00:00.000Z"
    time_unit = "MONTHLY"
    cost_filters {}
    name = "Sample Budget"
    cost_types {
        include_support = true
        include_other_subscription = true
        include_tax = true
        include_subscription = true
        use_blended = false
        include_upfront = true
        include_discount = true
        include_credit = false
        include_recurring = true
        use_amortized = false
        include_refund = false
    }
    budget_type = "COST"
}

resource "aws_budgets_budget" "BudgetsBudget2" {
    limit_amount = "50.0"
    limit_unit = "USD"
    time_period_end = "2087-06-15T00:00:00.000Z"
    time_period_start = "2021-08-01T00:00:00.000Z"
    time_unit = "MONTHLY"
    cost_filters {}
    name = "Real Month budget"
    cost_types {
        include_support = true
        include_other_subscription = true
        include_tax = true
        include_subscription = true
        use_blended = false
        include_upfront = true
        include_discount = true
        include_credit = false
        include_recurring = true
        use_amortized = false
        include_refund = false
    }
    budget_type = "COST"
}

resource "aws_elasticsearch_domain" "OpenSearchServiceDomain" {
    domain_name = "blog-es"
    elasticsearch_version = "OpenSearch_1.0"
    cluster_config {
        dedicated_master_count = 3
        dedicated_master_enabled = true
        dedicated_master_type = "t3.small.elasticsearch"
        instance_count = 2
        instance_type = "t3.small.elasticsearch"
        zone_awareness_enabled = true
    }
    access_policies  = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"es:*\",\"Resource\":\"arn:aws:es:ap-southeast-1:162387011843:domain/blog-es/*\"}]}"
    encrypt_at_rest {
        enabled = true
        kms_key_id = "arn:aws:kms:ap-southeast-1:162387011843:key/b0be90c2-68df-411b-b0a4-3387be2a310d"
    }
    node_to_node_encryption {
        enabled = true
    }
    advanced_options {
        indices.fielddata.cache.size = "20"
        indices.query.bool.max_clause_count = "1024"
        override_main_response_version = "false"
        rest.action.multi.allow_explicit_index = "true"
    }
    ebs_options {
        ebs_enabled = true
        volume_type = "gp2"
        volume_size = 10
    }
}

resource "aws_config_config_rule" "ConfigConfigRule" {
    name = "account-part-of-organizations"
    description = "Rule checks whether AWS account is part of AWS Organizations. The rule is NON_COMPLIANT if the AWS account is not part of AWS Organizations or AWS Organizations master account ID does not match rule parameter MasterAccountId."
    source {
        owner = "AWS"
        source_identifier = "ACCOUNT_PART_OF_ORGANIZATIONS"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "TwentyFour_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule2" {
    name = "alb-http-drop-invalid-header-enabled"
    description = "Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false."
    scope {
        compliance_resource_types = [
            "AWS::ElasticLoadBalancingV2::LoadBalancer"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"
    }
}

resource "aws_config_config_rule" "ConfigConfigRule3" {
    name = "ec2-security-group-attached-to-eni"
    description = "Checks that non-default security groups are attached to Amazon Elastic Compute Cloud (EC2) instances or an elastic network interfaces (ENIs). The rule returns NON_COMPLIANT if the security group is not associated with an EC2 instance or an ENI. "
    scope {
        compliance_resource_types = [
            "AWS::EC2::SecurityGroup"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"
    }
}

resource "aws_config_config_rule" "ConfigConfigRule4" {
    name = "securityhub-access-keys-rotated-659778c0"
    description = "Checks whether the active access keys are rotated within the number of days specified in maxAccessKeyAge"
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ACCESS_KEYS_ROTATED"
    }
    input_parameters = "{\"maxAccessKeyAge\":\"90\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule5" {
    name = "securityhub-acm-certificate-expiration-check-c8fe333a"
    description = "Imported ACM certificates should be renewed within the number of days specified."
    scope {
        compliance_resource_types = [
            "AWS::ACM::Certificate"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
    }
    input_parameters = "{\"daysToExpiration\":\"30\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule6" {
    name = "securityhub-alb-http-drop-invalid-header-enabled-36b55648"
    description = "Checks if rule evaluates Application Load Balancers (ALBs) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule7" {
    name = "securityhub-alb-http-to-https-redirection-check-870bc651"
    description = "Checks whether HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers. The rule is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancers do not have HTTP to HTTPS redirection configured."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule8" {
    name = "securityhub-api-gw-associated-with-waf-2fd736d5"
    description = "This control checks to see if an API Gateway stage is using an AWS WAF Web ACL. This control fails if an AWS WAF Web ACL is not attached to a REST API Gateway stage."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "API_GW_ASSOCIATED_WITH_WAF"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule9" {
    name = "securityhub-api-gw-cache-encrypted-2fb2acfa"
    description = "This control checks whether all methods in Amazon API Gateway REST API stages that have cache enabled are encrypted. The control fails if any method in API Gateway REST API stage is configured to cache and the cache is not encrypted."
    scope {
        compliance_resource_types = [
            "AWS::ApiGateway::Stage"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule10" {
    name = "securityhub-api-gw-execution-logging-enabled-d5a13eb1"
    description = "Checks that all stages in Amazon API Gateway REST and WebSocket APIs have logging enabled. The rule is NON_COMPLIANT if logging is not enabled. The rule is NON_COMPLIANT if loggingLevel is neither ERROR nor INFO."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "API_GW_EXECUTION_LOGGING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule11" {
    name = "securityhub-api-gw-ssl-enabled-8e1c00d5"
    description = "Checks if a REST API stage uses an Secure Sockets Layer (SSL) certificate. This rule is NON_COMPLIANT if the REST API stage does not have an associated SSL certificate."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "API_GW_SSL_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule12" {
    name = "securityhub-api-gw-xray-enabled-c0b81358"
    description = "Checks if AWS X-Ray tracing is enabled on Amazon API Gateway REST APIs. The rule is COMPLIANT if X-Ray tracing is enabled and NON_COMPLIANT otherwise."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "API_GW_XRAY_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule13" {
    name = "securityhub-aurora-mysql-backtracking-enabled-c05b8d07"
    description = "This control checks if Amazon Aurora clusters have backtracking enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "AURORA_MYSQL_BACKTRACKING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule14" {
    name = "securityhub-autoscaling-group-elb-healthcheck-required-49f514fd"
    description = "Checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks."
    scope {
        compliance_resource_types = [
            "AWS::AutoScaling::AutoScalingGroup"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule15" {
    name = "securityhub-beanstalk-enhanced-health-reporting-enabled-99db1358"
    description = "Checks for Elastic Beanstalk environment is configured for 'enhanced' health reporting and NON_COMPLIANT if configured for 'basic' health reporting."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "BEANSTALK_ENHANCED_HEALTH_REPORTING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule16" {
    name = "securityhub-cloud-trail-cloud-watch-logs-enabled-9be4514a"
    description = "Checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch logs."
    scope {
        compliance_resource_types = [
            "AWS::CloudTrail::Trail"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule17" {
    name = "securityhub-cloud-trail-encryption-enabled-6b7cf663"
    description = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
    scope {
        compliance_resource_types = [
            "AWS::CloudTrail::Trail"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule18" {
    name = "securityhub-cloud-trail-log-file-validation-enabled-0cad3327"
    description = "Checks whether AWS CloudTrail creates a signed digest file with logs."
    scope {
        compliance_resource_types = [
            "AWS::CloudTrail::Trail"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule19" {
    name = "securityhub-cmk-backing-key-rotation-enabled-b75a7f11"
    description = "Checks that key rotation is enabled for customer created customer master key (CMK)"
    scope {
        compliance_resource_types = [
            "AWS::KMS::Key"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule20" {
    name = "securityhub-codebuild-project-envvar-awscred-check-00831b03"
    description = "Checks whether the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
    scope {
        compliance_resource_types = [
            "AWS::CodeBuild::Project"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule21" {
    name = "securityhub-codebuild-project-source-repo-url-check-46a049ef"
    description = "Checks whether the GitHub or Bitbucket source repository URL contains either personal access tokens or user name and password."
    scope {
        compliance_resource_types = [
            "AWS::CodeBuild::Project"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule22" {
    name = "securityhub-dax-encryption-enabled-eac19ed1"
    description = "Checks that DynamoDB Accelerator (DAX) clusters are encrypted. The rule is NON_COMPLIANT if a DAX cluster is not encrypted."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "DAX_ENCRYPTION_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule23" {
    name = "securityhub-dms-replication-not-public-9b92958d"
    description = "Checks whether AWS Database Migration Service replication instances are public. The rule is NON_COMPLIANT if PubliclyAccessible field is true."
    scope {
        compliance_resource_types = [
            "AWS::DMS::ReplicationInstance"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "DMS_REPLICATION_NOT_PUBLIC"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule24" {
    name = "securityhub-dynamodb-autoscaling-enabled-e841754b"
    description = "Checks whether Auto Scaling or On-Demand is enabled on your DynamoDB tables and/or global secondary indexes. Optionally you can set the read and write capacity units for the table or global secondary index."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "DYNAMODB_AUTOSCALING_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule25" {
    name = "securityhub-dynamodb-pitr-enabled-38f0505a"
    description = "Checks that point in time recovery (PITR) is enabled for Amazon DynamoDB tables. The rule is NON_COMPLIANT if point in time recovery is not enabled for Amazon DynamoDB tables"
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "DYNAMODB_PITR_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule26" {
    name = "securityhub-ebs-snapshot-public-restorable-check-89f63339"
    description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule27" {
    name = "securityhub-ec2-ebs-encryption-by-default-34698011"
    description = "Checks that Amazon Elastic Block Store (EBS) encryption is enabled by default. The rule is NON_COMPLIANT if the encryption is not enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule28" {
    name = "securityhub-ec2-imdsv2-check-d85f9c66"
    description = "Checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2)."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_IMDSV2_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule29" {
    name = "securityhub-ec2-instance-managed-by-ssm-569acfad"
    description = "Checks whether the Amazon EC2 instances in your account are managed by AWS Systems Manager."
    scope {
        compliance_resource_types = [
            "AWS::EC2::Instance",
            "AWS::SSM::ManagedInstanceInventory"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule30" {
    name = "securityhub-ec2-instance-multiple-eni-check-f6e37be9"
    description = "This control checks to see if Amazon EC2 instance uses multiple ENI/EFA. This control will pass if single network adapters is used."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_INSTANCE_MULTIPLE_ENI_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule31" {
    name = "securityhub-ec2-instance-no-public-ip-4d4d5374"
    description = "Checks whether Amazon Elastic Compute Cloud (Amazon EC2) instances have a public IP association. The rule is NON_COMPLIANT if the publicIp field is present in the Amazon EC2 instance configuration item. This rule applies only to IPv4."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule32" {
    name = "securityhub-ec2-managedinstance-association-compliance-status-check-2e4c42e7"
    description = "Checks whether the compliance status of the Amazon EC2 Systems Manager association compliance is COMPLIANT or NON_COMPLIANT after the association execution on the instance. The rule is COMPLIANT if the field status is COMPLIANT."
    scope {
        compliance_resource_types = [
            "AWS::SSM::AssociationCompliance"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule33" {
    name = "securityhub-ec2-managedinstance-patch-compliance-a90a7acf"
    description = "Checks whether the compliance status of the Amazon EC2 Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance."
    scope {
        compliance_resource_types = [
            "AWS::SSM::PatchCompliance"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule34" {
    name = "securityhub-ec2-stopped-instance-654ebe79"
    description = "Checks whether there are instances stopped for more than the allowed number of days."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EC2_STOPPED_INSTANCE"
    }
    input_parameters = "{\"AllowedDays\":\"30\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule35" {
    name = "securityhub-ecs-service-assign-public-ip-disabled-9106491c"
    description = "This control checks whether ECS services are configured to automatically assign public IP addresses. This control fails if AssignPublicIP is ENABLED."
    scope {
        compliance_resource_types = [
            "AWS::ECS::Service"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{\"version\":\"1.1\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule36" {
    name = "securityhub-ecs-task-definition-user-for-host-mode-check-3aa5ec37"
    description = "This control checks if an Amazon ECS Task Definition with host networking mode has \"privileged\" or \"user\" container definitions. The control fails with host network mode and container definitions are privileged=false or empty and user=root or empty."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ECS_TASK_DEFINITION_USER_FOR_HOST_MODE_CHECK"
    }
    input_parameters = "{\"SkipInactiveTaskDefinitions\":\"true\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule37" {
    name = "securityhub-efs-encrypted-check-f337cbd5"
    description = "Elastic File System should be configured to encrypt file data at-rest using AWS KMS."
    scope {
        compliance_resource_types = [
            "AWS::EFS::FileSystem"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "EFS_ENCRYPTED_CHECK"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule38" {
    name = "securityhub-efs-in-backup-plan-cf7dc81e"
    description = "Checks whether Amazon Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup. The rule is NON_COMPLIANT if EFS file systems are not included in the backup plans."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EFS_IN_BACKUP_PLAN"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule39" {
    name = "securityhub-elastic-beanstalk-managed-updates-enabled-b567ecc6"
    description = "Checks if managed platform updates in an AWS Elastic Beanstalk environment is enabled. The rule is NON_COMPLIANT if the value for ‘ManagedActionsEnabled’ is set to false or if a parameter is provided whose value does not match the existing configurations."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELASTIC_BEANSTALK_MANAGED_UPDATES_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule40" {
    name = "securityhub-elasticsearch-audit-logging-enabled-ed7e1e34"
    description = "This control checks whether Elasticsearch domains have audit logging enabled. This control fails if an Elasticsearch domain does not have audit logging enabled."
    scope {
        compliance_resource_types = [
            "AWS::Elasticsearch::Domain"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule41" {
    name = "securityhub-elasticsearch-data-node-fault-tolerance-360c452d"
    description = "This control checks whether Elasticsearch domains are configured with at least three data nodes and zoneAwarenessEnabled is true."
    scope {
        compliance_resource_types = [
            "AWS::Elasticsearch::Domain"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule42" {
    name = "securityhub-elasticsearch-encrypted-at-rest-82e347a0"
    description = "Checks whether Elasticsearch domains have encryption at rest configuration enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELASTICSEARCH_ENCRYPTED_AT_REST"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule43" {
    name = "securityhub-elasticsearch-https-required-5ff85d73"
    description = "This control checks whether connections to Elasticsearch domains are required to use TLS 1.2.  The check fails if the Elasticsearch domain TLSSecurityPolicy is not Policy-Min-TLS-1-2-2019-07."
    scope {
        compliance_resource_types = [
            "AWS::Elasticsearch::Domain"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule44" {
    name = "securityhub-elasticsearch-in-vpc-only-5aa02656"
    description = "Checks whether Elasticsearch domains are in Amazon Virtual Private Cloud (Amazon VPC)."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELASTICSEARCH_IN_VPC_ONLY"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule45" {
    name = "securityhub-elasticsearch-logs-to-cloudwatch-d6c83ccc"
    description = "This control checks whether Elasticsearch domains are configured to send error logs to CloudWatch Logs."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELASTICSEARCH_LOGS_TO_CLOUDWATCH"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule46" {
    name = "securityhub-elasticsearch-node-to-node-encryption-check-c838a381"
    description = "Check that Elasticsearch nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is disabled on the domain."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule47" {
    name = "securityhub-elasticsearch-primary-node-fault-tolerance-274dff8f"
    description = "This control checks whether Elasticsearch domains are configured with at least three dedicated master nodes. This control fails if dedicatedMasterEnabled is not true."
    scope {
        compliance_resource_types = [
            "AWS::Elasticsearch::Domain"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule48" {
    name = "securityhub-elb-connection-draining-enabled-a5b5135f"
    description = "This control checks whether AWS Classic Load Balancers have connection draining enabled."
    scope {
        compliance_resource_types = [
            "AWS::ElasticLoadBalancing::LoadBalancer"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule49" {
    name = "securityhub-elb-deletion-protection-enabled-258d6c57"
    description = "Checks whether Elastic Load Balancing has deletion protection enabled. The rule is NON_COMPLIANT if deletion_protection.enabled is false."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELB_DELETION_PROTECTION_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule50" {
    name = "securityhub-elb-logging-enabled-796c7e82"
    description = "Checks whether the Application Load Balancer and the Classic Load Balancer have logging enabled. The rule is NON_COMPLIANT if the access_logs.s3.enabled is false or access_logs.S3.bucket is not equal to the s3BucketName that you provided."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELB_LOGGING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule51" {
    name = "securityhub-elb-tls-https-listeners-only-b3d8aae2"
    description = "Check whether your Classic Load Balancer listeners are configured with HTTPS or SSL protocol for front-end (client to load balancer)."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ELB_TLS_HTTPS_LISTENERS_ONLY"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule52" {
    name = "securityhub-emr-master-no-public-ip-cfe72f93"
    description = "Checks whether Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. The rule is NON_COMPLIANT if the master node has a public IP."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "EMR_MASTER_NO_PUBLIC_IP"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule53" {
    name = "securityhub-enabled"
    description = "Checks that AWS Security Hub is enabled for an AWS Account. The rule is NON_COMPLIANT if AWS Security Hub is not enabled."
    source {
        owner = "AWS"
        source_identifier = "SECURITYHUB_ENABLED"
    }
    maximum_execution_frequency = "TwentyFour_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule54" {
    name = "securityhub-encrypted-volumes-e65b47b8"
    description = "Checks whether the EBS volumes that are in an attached state are encrypted. If you specify the ID of a KMS key for encryption using the kmsId parameter, the rule checks if the EBS volumes in an attached state are encrypted with that KMS key."
    scope {
        compliance_resource_types = [
            "AWS::EC2::Volume"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "ENCRYPTED_VOLUMES"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule55" {
    name = "securityhub-guardduty-enabled-centralized-757940da"
    description = "This AWS control checks whether Amazon GuardDuty is enabled in your AWS account and region."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule56" {
    name = "securityhub-iam-customer-policy-blocked-kms-actions-b68b8693"
    description = "Checks that the managed AWS Identity and Access Management (IAM) policies that you create do not allow blocked actions on all AWS KMS keys. The rule is NON_COMPLIANT if any blocked action is allowed on all AWS KMS keys by the managed IAM policy."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_CUSTOMER_POLICY_BLOCKED_KMS_ACTIONS"
    }
    input_parameters = "{\"blockedActionsPatterns\":\"kms:Decrypt,kms:ReEncryptFrom\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule57" {
    name = "securityhub-iam-inline-policy-blocked-kms-actions-bafe49bd"
    description = "Checks that the inline policies attached to your IAM users, roles, and groups do not allow blocked actions on all AWS Key Management Service (KMS) keys. The rule is NON_COMPLIANT if any blocked action is allowed on all KMS keys in an inline policy."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_INLINE_POLICY_BLOCKED_KMS_ACTIONS"
    }
    input_parameters = "{\"blockedActionsPatterns\":\"kms:Decrypt,kms:ReEncryptFrom\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule58" {
    name = "securityhub-iam-password-policy-ensure-expires-4376324d"
    description = "Checks whether the account password policy for IAM users expires passwords within certain days"
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"MaxPasswordAge\":\"90\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule59" {
    name = "securityhub-iam-password-policy-lowercase-letter-check-89be3bd7"
    description = "Checks whether the account password policy for IAM users requires at least one lowercase character in password."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"RequireLowercaseCharacters\":\"true\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule60" {
    name = "securityhub-iam-password-policy-minimum-length-check-78253c92"
    description = "Checks whether the account password policy for IAM users requires minimum password length."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"MinimumPasswordLength\":\"14\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule61" {
    name = "securityhub-iam-password-policy-number-check-0f54a54b"
    description = "Checks whether the account password policy for IAM users requires at least one number in password."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"RequireNumbers\":\"true\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule62" {
    name = "securityhub-iam-password-policy-prevent-reuse-check-41e3d11f"
    description = "Checks whether the account password policy for IAM users prevents password reuse."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"PasswordReusePrevention\":\"24\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule63" {
    name = "securityhub-iam-password-policy-recommended-defaults-d0584e5f"
    description = "Checks whether the account password policy for IAM users meets the specified requirements."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"MinimumPasswordLength\":\"8\",\"RequireLowercaseCharacters\":\"true\",\"RequireNumbers\":\"true\",\"RequireUppercaseCharacters\":\"true\",\"RequireSymbols\":\"true\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule64" {
    name = "securityhub-iam-password-policy-symbol-check-ca559bcf"
    description = "Checks whether the account password policy for IAM users requires at least one symbol in password."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"RequireSymbols\":\"true\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule65" {
    name = "securityhub-iam-password-policy-uppercase-letter-check-6bbf729f"
    description = "Checks whether the account password policy for IAM users requires at least one uppercase character in password."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_PASSWORD_POLICY"
    }
    input_parameters = "{\"RequireUppercaseCharacters\":\"true\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule66" {
    name = "securityhub-iam-policy-no-statements-with-admin-access-a83d7ab9"
    description = "Checks whether the default version of IAM policies have administrator access"
    scope {
        compliance_resource_types = [
            "AWS::IAM::Policy"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule67" {
    name = "securityhub-iam-policy-no-statements-with-full-access-b28504bc"
    description = "This control checks whether the IAM identity-based custom policies have Allow statements that grant permissions for all actions on a service. The control fails if any policy statement includes \"Effect\": \"Allow\" with \"Action\": \"Service:*\"."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule68" {
    name = "securityhub-iam-root-access-key-check-c5bf5209"
    description = "Checks whether the root user access key is available."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule69" {
    name = "securityhub-iam-support-policy-in-use-e256c9c2"
    description = "Checks that the 'AWSSupportAccess' managed policy is attached to any IAM user, group, or role."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_POLICY_IN_USE"
    }
    input_parameters = "{\"policyARN\":\"arn:aws:iam::aws:policy/AWSSupportAccess\",\"policyUsageType\":\"ANY\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule70" {
    name = "securityhub-iam-user-no-policies-check-fda6acef"
    description = "Checks that none of your IAM users have policies attached. IAM users must inherit permissions from IAM groups or roles."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_USER_NO_POLICIES_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule71" {
    name = "securityhub-iam-user-unused-credentials-check-4db2a9ac"
    description = "This control checks whether your IAM users have passwords or active access keys that were not used within the previous 90 days."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
    }
    input_parameters = "{\"maxCredentialUsageAge\":\"90\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule72" {
    name = "securityhub-kms-cmk-not-scheduled-for-deletion-2-7070e1af"
    description = "This control checks whether AWS Key Management Service (KMS) customer managed keys (CMK) are scheduled for deletion. The control fails if a KMS CMK is scheduled for deletion."
    scope {
        compliance_resource_types = [
            "AWS::KMS::Key"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule73" {
    name = "securityhub-lambda-function-public-access-prohibited-36a79484"
    description = "Checks whether the AWS Lambda function policy attached to the Lambda resource prohibits public access."
    scope {
        compliance_resource_types = [
            "AWS::Lambda::Function"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule74" {
    name = "securityhub-lambda-function-settings-check-0dc3f44b"
    description = "Checks that the AWS Lambda function settings for runtime, role, timeout, and memory size match the expected values."
    scope {
        compliance_resource_types = [
            "AWS::Lambda::Function"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "LAMBDA_FUNCTION_SETTINGS_CHECK"
    }
    input_parameters = "{\"runtime\":\"nodejs14.x,nodejs12.x,python3.9,python3.8,python3.7,python3.6,java11,java8,java8.al2,go1.x,dotnetcore3.1,ruby2.7\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule75" {
    name = "securityhub-mfa-enabled-for-iam-console-access-07d96477"
    description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password."
    scope {
        compliance_resource_types = [
            "AWS::IAM::User"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule76" {
    name = "securityhub-multi-region-cloud-trail-enabled-55586773"
    description = "Checks whether AWS CloudTrail is enabled in your AWS account. Optionally, you can specify which S3 bucket, SNS topic, and Amazon CloudWatch Logs ARN to use."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
    }
    input_parameters = "{\"readWriteType\":\"ALL\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule77" {
    name = "securityhub-rds-automatic-minor-version-upgrade-enabled-869eb42e"
    description = "This control checks if automatic minor version upgrades are enabled for the Amazon RDS database instance."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_AUTOMATIC_MINOR_VERSION_UPGRADE_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule78" {
    name = "securityhub-rds-cluster-copy-tags-to-snapshots-enabled-2f627329"
    description = "This control checks whether RDS DB clusters are configured to copy all tags to snapshots when the snapshots are created."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBCluster"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{\"version\":\"1.1\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule79" {
    name = "securityhub-rds-cluster-deletion-protection-enabled-0768d6e0"
    description = "Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled. This rule is NON_COMPLIANT if an RDS cluster does not have deletion protection enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_CLUSTER_DELETION_PROTECTION_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule80" {
    name = "securityhub-rds-cluster-event-notifications-configured-630875f0"
    description = "This control checks whether an Amazon RDS Event subscription for RDS clusters is configured to notify on event categories of both \"maintenance\" and \"failure\"."
    scope {
        compliance_resource_types = [
            "AWS::RDS::EventSubscription"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule81" {
    name = "securityhub-rds-cluster-iam-authentication-enabled-300b4d2a"
    description = "Checks if an Amazon RDS Cluster has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an RDS Cluster does not have IAM authentication enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_CLUSTER_IAM_AUTHENTICATION_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule82" {
    name = "securityhub-rds-cluster-multi-az-enabled-68b67561"
    description = "This control checks if RDS DB clusters are configured with multi-az."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_CLUSTER_MULTI_AZ_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule83" {
    name = "securityhub-rds-deployed-in-vpc-5243fd77"
    description = "This control checks if an RDS instance is deployed in a VPC (EC2-VPC)."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBInstance"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule84" {
    name = "securityhub-rds-enhanced-monitoring-enabled-3e16db16"
    description = "Checks whether enhanced monitoring is enabled for Amazon Relational Database Service (Amazon RDS) instances."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_ENHANCED_MONITORING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule85" {
    name = "securityhub-rds-instance-copy-tags-to-snapshots-enabled-bfce8d75"
    description = "This control checks whether RDS DB instances are configured to copy all tags to snapshots when the snapshots are created."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBInstance"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule86" {
    name = "securityhub-rds-instance-deletion-protection-enabled-9e3dc26a"
    description = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has deletion protection enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
    }
    input_parameters = "{\"databaseEngines\":\"mariadb,mysql,oracle-ee,oracle-se2,oracle-se1,oracle-se,postgres,sqlserver-ee,sqlserver-se,sqlserver-ex,sqlserver-web\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule87" {
    name = "securityhub-rds-instance-event-notifications-configured-1a957676"
    description = "This control checks whether an Amazon RDS Event subscription for RDS instances is configured to notify on event categories of both \"maintenance\", \"configuration change\", and \"failure\"."
    scope {
        compliance_resource_types = [
            "AWS::RDS::EventSubscription"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule88" {
    name = "securityhub-rds-instance-iam-authentication-enabled-089f7812"
    description = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has AWS Identity and Access Management (IAM) authentication enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_INSTANCE_IAM_AUTHENTICATION_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule89" {
    name = "securityhub-rds-instance-public-access-check-ff3958ab"
    description = "Check whether the Amazon Relational Database Service instances are not publicly accessible."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBInstance"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule90" {
    name = "securityhub-rds-logging-enabled-aa686043"
    description = "Checks that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled. The rule is NON_COMPLIANT if any log types are not enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_LOGGING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule91" {
    name = "securityhub-rds-multi-az-support-553bd0e0"
    description = "Checks whether high availability is enabled for your RDS DB instances."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_MULTI_AZ_SUPPORT"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule92" {
    name = "securityhub-rds-no-default-ports-f70b4a6c"
    description = "This control checks whether RDS instances use the default port of that database engine."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBInstance"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule93" {
    name = "securityhub-rds-pg-event-notifications-configured-278a1c14"
    description = "This control checks whether an Amazon RDS Event subscription for RDS parameter groups is configured to notify on event category of \"configuration change\"."
    scope {
        compliance_resource_types = [
            "AWS::RDS::EventSubscription"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule94" {
    name = "securityhub-rds-sg-event-notifications-configured-c0841c56"
    description = "This control checks whether an Amazon RDS Event subscription for RDS security groups is configured to notify on event categories of both \"configuration change\" and \"failure\"."
    scope {
        compliance_resource_types = [
            "AWS::RDS::EventSubscription"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule95" {
    name = "securityhub-rds-snapshot-encrypted-50f51287"
    description = "Checks whether Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted. The rule is NON_COMPLIANT, if Amazon RDS DB snapshots are not encrypted."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_SNAPSHOT_ENCRYPTED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule96" {
    name = "securityhub-rds-snapshots-public-prohibited-bfd73dd3"
    description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBSnapshot",
            "AWS::RDS::DBClusterSnapshot"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule97" {
    name = "securityhub-rds-storage-encrypted-4eec57cb"
    description = "Checks whether storage encryption is enabled for your RDS DB instances."
    scope {
        compliance_resource_types = [
            "AWS::RDS::DBInstance"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "RDS_STORAGE_ENCRYPTED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule98" {
    name = "securityhub-redshift-backup-enabled-9ff03cee"
    description = "Checks that Amazon Redshift automated snapshots are enabled for clusters. The rule is NON_COMPLIANT if the value for automatedSnapshotRetentionPeriod is greater than MaxRetentionPeriod or less than MinRetentionPeriod or the value is 0."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "REDSHIFT_BACKUP_ENABLED"
    }
    input_parameters = "{\"MinRetentionPeriod\":\"7\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule99" {
    name = "securityhub-redshift-cluster-audit-logging-enabled-948727ec"
    description = "This control checks whether the Amazon Redshift cluster has audit logging enabled."
    scope {
        compliance_resource_types = [
            "AWS::Redshift::Cluster"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{\"loggingEnabled\":\"true\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule100" {
    name = "securityhub-redshift-cluster-maintenancesettings-check-a19e5cca"
    description = "Checks whether Amazon Redshift clusters have the specified maintenance settings."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK"
    }
    input_parameters = "{\"allowVersionUpgrade\":\"true\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule101" {
    name = "securityhub-redshift-cluster-public-access-check-0f8e096d"
    description = "Checks whether Amazon Redshift clusters are not publicly accessible."
    scope {
        compliance_resource_types = [
            "AWS::Redshift::Cluster"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule102" {
    name = "securityhub-redshift-enhanced-vpc-routing-enabled-6b35bb6b"
    description = "This control checks whether a Redshift cluster has EnhancedVpcRouting enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "REDSHIFT_ENHANCED_VPC_ROUTING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule103" {
    name = "securityhub-redshift-require-tls-ssl-22462935"
    description = "Checks whether Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. The rule is NON_COMPLIANT if any Amazon Redshift cluster has parameter require_SSL not set to true."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "REDSHIFT_REQUIRE_TLS_SSL"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule104" {
    name = "securityhub-restricted-rdp-f6dcc4c7"
    description = "Checks whether the incoming RDP traffic is Allowed from 0.0.0.0/0. This rule is compliant when incoming RDP traffic is restricted."
    scope {
        compliance_resource_types = [
            "AWS::EC2::SecurityGroup"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
    }
    input_parameters = "{\"blockedPort1\":\"3389\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule105" {
    name = "securityhub-restricted-ssh-dd87c008"
    description = "Checks whether the incoming SSH traffic for the security groups is accessible. The rule is compliant when the IP addresses of the incoming SSH traffic in the security groups are restricted. This rule applies only to IPv4."
    scope {
        compliance_resource_types = [
            "AWS::EC2::SecurityGroup"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "INCOMING_SSH_DISABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule106" {
    name = "securityhub-root-account-hardware-mfa-enabled-46679cf4"
    description = "Checks whether users of your AWS account require a hardware multi-factor authentication (MFA) device to sign in with root credentials."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule107" {
    name = "securityhub-root-account-mfa-enabled-5e3dba94"
    description = "Checks whether users of your AWS account require a multi-factor authentication (MFA) device to sign in with root credentials."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule108" {
    name = "securityhub-s3-account-level-public-access-blocks-periodic-a980ac9e"
    description = "Checks if the required public access block settings are configured from account level."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC"
    }
    input_parameters = "{\"RestrictPublicBuckets\":\"True\",\"BlockPublicPolicy\":\"True\",\"BlockPublicAcls\":\"True\",\"IgnorePublicAcls\":\"True\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule109" {
    name = "securityhub-s3-bucket-blacklisted-actions-prohibited-490024f0"
    description = "Checks that the Amazon Simple Storage Service bucket policy does not allow blacklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED"
    }
    input_parameters = "{\"blacklistedActionPattern\":\"s3:DeleteBucketPolicy,s3:PutBucketAcl,s3:PutBucketPolicy,s3:PutObjectAcl,s3:PutEncryptionConfiguration\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule110" {
    name = "securityhub-s3-bucket-level-public-access-prohibited-431775d8"
    description = "This control checks if Amazon S3 buckets have bucket level public access blocks applied. This control fails if any of the bucket level settings are set to \"false\" public: ignorePublicAcls, blockPublicPolicy, blockPublicAcls, restrictPublicBuckets."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule111" {
    name = "securityhub-s3-bucket-logging-enabled-1e731d5f"
    description = "Checks whether logging is enabled for your S3 buckets."
    scope {
        compliance_resource_types = [
            "AWS::S3::Bucket"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_LOGGING_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule112" {
    name = "securityhub-s3-bucket-public-read-prohibited-1bf866c5"
    description = "Checks to see if S3 buckets are publicly readable."
    scope {
        compliance_resource_types = [
            "AWS::S3::Bucket"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule113" {
    name = "securityhub-s3-bucket-public-write-prohibited-8dfc70cd"
    description = "Checks to see if S3 buckets allow public write."
    scope {
        compliance_resource_types = [
            "AWS::S3::Bucket"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule114" {
    name = "securityhub-s3-bucket-server-side-encryption-enabled-406a72e1"
    description = "Checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled or that the S3 bucket policy explicitly denies put-object requests without server side encryption."
    scope {
        compliance_resource_types = [
            "AWS::S3::Bucket"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule115" {
    name = "securityhub-s3-bucket-ssl-requests-only-a604b23e"
    description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."
    scope {
        compliance_resource_types = [
            "AWS::S3::Bucket"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule116" {
    name = "securityhub-sagemaker-notebook-no-direct-internet-access-17d6866a"
    description = "Checks whether direct internet access is disabled for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if Amazon SageMaker notebook instances are internet-enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule117" {
    name = "securityhub-secretsmanager-rotation-enabled-check-deccaefd"
    description = "Checks whether AWS Secrets Manager secret has rotation enabled."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SECRETSMANAGER_ROTATION_ENABLED_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule118" {
    name = "securityhub-secretsmanager-scheduled-rotation-success-check-e5825222"
    description = "Checks and verifies whether AWS Secrets Manager secret rotation has rotated successfully as per the rotation schedule. The rule is NON_COMPLIANT if RotationOccurringAsScheduled is false."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule119" {
    name = "securityhub-secretsmanager-secret-periodic-rotation-78915c18"
    description = "This control checks if your secrets have rotated at least once within 90 days. "
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SECRETSMANAGER_SECRET_PERIODIC_ROTATION"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule120" {
    name = "securityhub-secretsmanager-secret-unused-9d499499"
    description = "This control checks whether your secrets have been accessed within a specified number of days. The default value is 90 days. Secrets that have not been accessed even once within the number days you define, fail this check."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SECRETSMANAGER_SECRET_UNUSED"
    }
    input_parameters = "{}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule121" {
    name = "securityhub-service-vpc-endpoint-enabled-c48457eb"
    description = "Checks whether Service Endpoint for the service provided in rule parameter is created for each Amazon VPC. The rule returns NON_COMPLIANT if an Amazon VPC doesn't have a VPC endpoint created for the service."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SERVICE_VPC_ENDPOINT_ENABLED"
    }
    input_parameters = "{\"serviceName\":\"ec2\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule122" {
    name = "securityhub-sns-encrypted-kms-b348dddc"
    description = "Checks whether Amazon SNS topic is encrypted with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the Amazon SNS topic is not encrypted with AWS KMS."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SNS_ENCRYPTED_KMS"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule123" {
    name = "securityhub-sqs-queue-encrypted-9569a69b"
    description = "This control checks whether Amazon SQS queues are encrypted at rest."
    scope {
        compliance_resource_types = [
            "AWS::SQS::Queue"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule124" {
    name = "securityhub-subnet-auto-assign-public-ip-disabled-6f972dba"
    description = "Checks if Amazon Virtual Private Cloud (Amazon VPC) subnets are assigned a public IP address. This rule is NON_COMPLIANT if Amazon VPC has subnets that are assigned a public IP address."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule125" {
    name = "securityhub-vpc-default-security-group-closed-6aae365d"
    description = "Checks whether the default security group for VPC is closed."
    scope {
        compliance_resource_types = [
            "AWS::EC2::SecurityGroup"
        ]
    }
    source {
        owner = "AWS"
        source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule126" {
    name = "securityhub-vpc-flow-logs-enabled-7355a507"
    description = "Checks whether Amazon Virtual Private Cloud flow logs are found and enabled for Amazon VPC."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "VPC_FLOW_LOGS_ENABLED"
    }
    input_parameters = "{\"trafficType\":\"REJECT\"}"
    maximum_execution_frequency = "Twelve_Hours"
}

resource "aws_config_config_rule" "ConfigConfigRule127" {
    name = "securityhub-vpc-network-acl-unused-check-8ade2560"
    description = "Checks if there are unused Network Access Control Lists (NACLs). The rule is NON_COMPLIANT if an NACL is not associated with a subnet."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "VPC_NETWORK_ACL_UNUSED_CHECK"
    }
    input_parameters = "{}"
}

resource "aws_config_config_rule" "ConfigConfigRule128" {
    name = "securityhub-vpc-sg-open-only-to-authorized-ports-fd6f7149"
    description = "This control checks whether the security groups allow unrestricted incoming traffic. The control fails if ports allow unrestricted traffic on ports other than 80 and 443, which are default values for parameter authorizedTcpPorts."
    scope {
        
    }
    source {
        owner = "AWS"
        source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
    }
    input_parameters = "{\"authorizedTcpPorts\":\"80,443\"}"
}

resource "aws_config_config_rule" "ConfigConfigRule129" {
    name = "securityhub-vpc-sg-restricted-common-ports-993001ff"
    description = "This control checks whether unrestricted incoming traffic for the security groups is accessible to the specified ports [3389, 20, 23, 110, 143, 3306, 8080, 1433, 9200, 9300, 25, 445, 135, 21, 1434, 4333, 5432, 5500, 5601, 22] that have the highest risk."
    scope {
        compliance_resource_types = [
            "AWS::EC2::SecurityGroup"
        ]
    }
    source {
        owner = "CUSTOM_LAMBDA"
        source_identifier = "arn:aws:lambda:ap-southeast-1:338458120468:function:SecurityHubConfigRule"
        source_detail {
            
        }
    }
    input_parameters = "{}"
}

resource "aws_config_configuration_recorder" "ConfigConfigurationRecorder" {
    name = "default"
    recording_group {
        all_supported = true
        include_global_resource_types = true
    }
    role_arn = "arn:aws:iam::162387011843:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
}

resource "aws_config_delivery_channel" "ConfigDeliveryChannel" {
    name = "default"
    s3_bucket_name = "config-bucket-162387011843"
}

resource "aws_cognito_user_pool" "CognitoUserPool" {
    name = "edTech-user-pool"
    password_policy {
        minimum_length = 8
        require_lowercase = true
        require_numbers = true
        require_symbols = true
        require_uppercase = true
    }
    lambda_config {
        
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = false
        name = "sub"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "1"
        }
        required = true
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "name"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "given_name"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "family_name"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "middle_name"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "nickname"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "preferred_username"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "profile"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "picture"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "website"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "email"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = true
    }
    schema {
        attribute_data_type = "Boolean"
        developer_only_attribute = false
        mutable = true
        name = "email_verified"
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "gender"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "birthdate"
        string_attribute_constraints {
            max_length = "10"
            min_length = "10"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "zoneinfo"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "locale"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "phone_number"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "Boolean"
        developer_only_attribute = false
        mutable = true
        name = "phone_number_verified"
        required = false
    }
    schema {
        attribute_data_type = "String"
        developer_only_attribute = false
        mutable = true
        name = "address"
        string_attribute_constraints {
            max_length = "2048"
            min_length = "0"
        }
        required = false
    }
    schema {
        attribute_data_type = "Number"
        developer_only_attribute = false
        mutable = true
        name = "updated_at"
        number_attribute_constraints {
            min_value = "0"
        }
        required = false
    }
    auto_verified_attributes = [
        "email"
    ]
    username_attributes = [
        "email"
    ]
    sms_verification_message = "Your verification code is {####}. "
    email_verification_message = "Your verification code is {####}. "
    email_verification_subject = "Your verification code"
    sms_authentication_message = "Your verification code is {####}. "
    mfa_configuration = "OPTIONAL"
    device_configuration {
        challenge_required_on_new_device = false
        device_only_remembered_on_user_prompt = true
    }
    email_configuration {
        
    }
    sms_configuration {
        external_id = "c1c7e8a8-fc13-4b6e-bfd9-c284f731152b"
        sns_caller_arn = "${aws_iam_role.IAMRole10.arn}"
    }
    admin_create_user_config {
        allow_admin_create_user_only = false
        invite_message_template {
            email_message = "Your username is {username} and temporary password is {####}. "
            email_subject = "Your temporary password"
            sms_message = "Your username is {username} and temporary password is {####}. "
        }
        unused_account_validity_days = 7
    }
    tags {
        Name = "CognitoUserPool"
    }
}

resource "aws_cognito_user_pool_client" "CognitoUserPoolClient" {
    user_pool_id = "${aws_cognito_user_pool.CognitoUserPool.id}"
    name = "frontend_userpool"
    refresh_token_validity = 30
    read_attributes = [
        "address",
        "birthdate",
        "email",
        "email_verified",
        "family_name",
        "gender",
        "given_name",
        "locale",
        "middle_name",
        "name",
        "nickname",
        "phone_number",
        "phone_number_verified",
        "picture",
        "preferred_username",
        "profile",
        "updated_at",
        "website",
        "zoneinfo"
    ]
    write_attributes = [
        "address",
        "birthdate",
        "email",
        "family_name",
        "gender",
        "given_name",
        "locale",
        "middle_name",
        "name",
        "nickname",
        "phone_number",
        "picture",
        "preferred_username",
        "profile",
        "updated_at",
        "website",
        "zoneinfo"
    ]
    explicit_auth_flows = [
        "ALLOW_CUSTOM_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
        "ALLOW_USER_SRP_AUTH"
    ]
}

resource "aws_guardduty_detector" "GuardDutyDetector" {
    enable = true
    finding_publishing_frequency = "SIX_HOURS"
}

resource "aws_securityhub_account" "SecurityHubHub" {}
