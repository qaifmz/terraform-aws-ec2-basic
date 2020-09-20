data "aws_caller_identity" "this" {}
data "aws_region" "current" {}
terraform {
  required_version = ">= 0.12"
}

locals {
  name = var.name
  common_tags = {
    "Name"      = local.name
    "Terraform" = true
    "Region"    = data.aws_region.current.name
  }

  tags = merge(var.tags, local.common_tags)
}

variable "number_of_instances" {
  description = "Number of instances to create and attach to ELB"
  default     = 1
}

resource "random_pet" "this" {}

##########
# instance
##########

resource "aws_instance" "this" {
  count = var.create ? 1 : 0

  instance_type = var.instance_type
  ami           = var.ami_id == "" ? data.aws_ami.ubuntu.id : var.ami_id

  user_data = var.user_data == "" ? data.template_file.user_data.rendered : var.user_data

  subnet_id = module.vpc.public_subnets[0]

  vpc_security_group_ids = var.vpc_security_group_ids == null ? [module.security_group.this_security_group_id] : var.vpc_security_group_ids

  monitoring = var.monitoring

  iam_instance_profile = var.instance_profile_id == "" ? join("", aws_iam_instance_profile.this.*.id) : var.instance_profile_id
  key_name             = var.key_name == "" ? aws_key_pair.this[0].key_name : var.key_name

  root_block_device {
    volume_type           = "gp2"
    volume_size           = var.root_volume_size
    delete_on_termination = true
  }

  //  lifecycle {
  //  https://github.com/hashicorp/terraform/issues/22544
  //    prevent_destroy = var.ec2_prevent_destroy
  //  }

  tags = local.tags
}

###########
# user-data
###########

data "template_file" "user_data" {
  template = file("${path.module}/data/${var.user_data_script}")
}

#############
# default vpc
#############

# resource "aws_default_vpc" "this" {}

# data "aws_vpc" "default" {
#   default = true
# }

# data "aws_subnet_ids" "default" {
#   vpc_id = data.aws_vpc.default.id
# }

# data "aws_subnet" "default" {
#   count = length(data.aws_subnet_ids.default.ids)
#   id    = tolist(data.aws_subnet_ids.default.ids)[count.index]
# }
variable "vpc_name" {
  description = "The name of the VPC"
  type        = string
  default     = "default"
}

variable "azs" {
  description = "List of availability zones"
  type        = list(string)
  default     = []
}

variable "num_azs" {
  description = "The number of AZs to deploy into"
  type        = number
  default     = 3
}

variable "cidr" {
  description = "The cidr range for network"
  type        = string
  default     = "10.0.0.0/16"
}

locals {
  //    Logic for AZs is azs variable > az_num variable > max azs for region
  az_num = chunklist(data.aws_availability_zones.available.names, var.num_azs)[0]
  az_max = data.aws_availability_zones.available.names
  azs    = coalescelist(var.azs, local.az_num, local.az_max)

  num_azs      = length(local.azs)
  subnet_num   = 2
  subnet_count = local.subnet_num * local.num_azs

  subnet_bits = ceil(log(local.subnet_count, 2))

  public_subnets = [for subnet_num in range(local.num_azs) : cidrsubnet(
    var.cidr,
    local.subnet_bits,
  subnet_num)]

  private_subnets = [for subnet_num in range(local.num_azs) : cidrsubnet(
    var.cidr,
    local.subnet_bits,
    local.num_azs + subnet_num,
  )]
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source = "github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=v2.15.0"
  name   = var.vpc_name

  tags = var.tags

  enable_nat_gateway     = false
  single_nat_gateway     = false
  one_nat_gateway_per_az = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  azs  = local.azs
  cidr = var.cidr

  public_subnets  = local.public_subnets
  private_subnets = local.private_subnets
}

#################
# security groups
#################

module "security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 3.0"

  create = var.vpc_security_group_ids == null && var.create ? true : false

  name        = "${var.name}-${random_pet.this.id}"
  description = "Default security group if no security groups ids are supplied"

  vpc_id = module.vpc.name

  ingress_rules = var.ingress_rules
  egress_rules  = var.egress_rules

  ingress_cidr_blocks      = var.ingress_cidr_blocks
  ingress_with_cidr_blocks = var.ingress_with_cidr_blocks
}

############
# elastic ip
############

resource "aws_eip" "this" {
  count = var.create_eip && var.create ? 1 : 0

  vpc = true

  lifecycle {
    prevent_destroy = false
  }

  tags = local.tags
}

resource "aws_eip_association" "this" {
  count = var.create_eip && var.create ? 1 : 0

  allocation_id = join("", aws_eip.this.*.id)
  instance_id   = join("", aws_instance.this.*.id)
}

#############
# default AMI
#############

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name = "name"
    values = [
    "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name = "virtualization-type"
    values = [
    "hvm"]
  }

  owners = [
  "099720109477"]
  # Canonical
}

############
# ebs volume
############

resource "aws_ebs_volume" "this" {
  count = var.ebs_volume_size > 0 && var.create ? 1 : 0

  availability_zone = join("", aws_instance.this.*.availability_zone)

  size = var.ebs_volume_size
  type = "gp2"

  //  lifecycle {
  //  https://github.com/hashicorp/terraform/issues/22544
  //    prevent_destroy = var.ebs_prevent_destroy
  //  }

  tags = local.tags
}

resource "aws_volume_attachment" "this" {
  count = var.ebs_volume_size > 0 && var.create ? 1 : 0

  device_name = var.volume_path

  volume_id = var.ebs_volume_id == "" ? join("", aws_ebs_volume.this.*.id) : var.ebs_volume_id

  instance_id  = join("", aws_instance.this.*.id)
  force_detach = true
}

######################
# IAM instance profile
######################

resource "aws_iam_role" "this" {
  count              = var.instance_profile_id == "" && var.create ? 1 : 0
  name               = "${title(local.name)}-${random_pet.this.id}"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = local.tags
}

resource "aws_iam_instance_profile" "this" {
  count = var.instance_profile_id == "" && var.create ? 1 : 0

  name = "${title(local.name)}InstanceProfile-${random_pet.this.id}"
  role = join("", aws_iam_role.this.*.name)
}

#########################
# Additional IAM policies
#########################

resource "aws_iam_role_policy_attachment" "managed_policy" {
  count = var.instance_profile_id == "" && var.create ? length(var.iam_managed_policies) : 0
  role  = join("", aws_iam_role.this.*.id)

  policy_arn = "arn:aws:iam::aws:policy/${var.iam_managed_policies[count.index]}"
}

resource "aws_iam_policy" "json_policy" {
  count       = var.instance_profile_id == "" && var.json_policy_name != "" && var.create ? 1 : 0
  name        = var.json_policy_name
  description = "A user defined policy for the instance"

  policy = var.json_policy
}

resource "aws_iam_role_policy_attachment" "json_policy" {
  count = var.instance_profile_id == "" && var.json_policy_name != "" && var.create ? 1 : 0
  role  = join("", aws_iam_role.this.*.id)

  policy_arn = join("", aws_iam_policy.json_policy.*.arn)
}

#########
# keypair
#########

resource "tls_private_key" "this" {
  algorithm = "RSA"
}

resource "aws_key_pair" "this" {
  count    = var.key_name == "" && var.create ? 1 : 0
  key_name = "${local.name}-${random_pet.this.id}"
  # public_key = file(var.local_public_key)
  public_key = tls_private_key.this.public_key_openssh
}

#########################
# S3 bucket for ELB logs
#########################
data "aws_elb_service_account" "this" {}

resource "aws_s3_bucket" "logs" {
  bucket        = "elb-logs-${random_pet.this.id}"
  acl           = "private"
  policy        = data.aws_iam_policy_document.logs.json
  force_destroy = true
}

data "aws_iam_policy_document" "logs" {
  statement {
    actions = [
      "s3:PutObject",
    ]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.this.arn]
    }

    resources = [
      "arn:aws:s3:::elb-logs-${random_pet.this.id}/*",
    ]
  }
}

# ##################
# ACM certificate
##################
resource "aws_route53_zone" "this" {
  name          = "elbexample.com"
  force_destroy = true
}

module "acm" {
  source  = "terraform-aws-modules/acm/aws"
  version = "~> 2.0"

  zone_id = aws_route53_zone.this.zone_id

  domain_name               = "elbexample.com"
  subject_alternative_names = ["*.elbexample.com"]

  wait_for_validation = false
}

########
# ELB
########

module "elb" {
  source  = "terraform-aws-modules/elb/aws"
  version = "~> 2.0"

  name = "elb"

  subnets         = module.vpc.public_subnets
  security_groups = var.vpc_security_group_ids == null ? [module.security_group.this_security_group_id] : var.vpc_security_group_ids
  internal        = false

  listener = [
    {
      instance_port     = "80"
      instance_protocol = "HTTP"
      lb_port           = "80"
      lb_protocol       = "HTTP"
    },
    {
      instance_port     = "8080"
      instance_protocol = "http"
      lb_port           = "8080"
      lb_protocol       = "http"
      # ssl_certificate_id = "arn:aws:acm:eu-west-1:235367859451:certificate/6c270328-2cd5-4b2d-8dfd-ae8d0004ad31"
    },
  ]

  health_check = {
    target              = "HTTP:80/"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 5
  }

  access_logs = {
    bucket = aws_s3_bucket.logs.id
  }

  // ELB attachments
  number_of_instances = var.number_of_instances
  instances           = aws_instance.this.*.id

  tags = {
    Owner       = "user"
    Environment = "dev"
  }
}
