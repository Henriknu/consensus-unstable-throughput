packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.1"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

variable "ami_instance_type" {
  type    = string
  default = "t2.micro"
}

locals {
  timestamp = regex_replace(timestamp(), "[- TZ:]", "")
}

source "amazon-ebs" "ubuntu" {

  ami_name      = "abft-ubuntu-ami-${var.ami_instance_type}-${local.timestamp}"
  instance_type = "${var.ami_instance_type}"
  region        = "us-east-2"
  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"
}

build {
  sources = [
    "source.amazon-ebs.ubuntu"
  ]

  # Package install
  provisioner "shell" {
    inline = [
      "echo Installing required packages",
      "sudo add-apt-repository main && sudo add-apt-repository universe && sudo add-apt-repository multiverse && sudo add-apt-repository restricted",
      "sudo apt-get update -y",
      "sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y",
      "sudo apt-get install -y iproute2 dtach build-essential make automake autoconf libtool",
    ]
  }

  # AWS Cloud Watch Agent install
  provisioner "shell" {
    inline = [
      "echo Installing AWS Cloud Watch Agent",
      "wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb",
      "sudo dpkg -i -E ./amazon-cloudwatch-agent.deb",
      "rm ./amazon-cloudwatch-agent.deb"
    ]
  }

   # Preparing folder structure
  provisioner "shell" {
    inline = [
      "echo Preparing folder structure",
      "mkdir crypto",
      "mkdir logs",
    ]
  }



  


}