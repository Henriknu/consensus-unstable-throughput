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
      "sudo apt-get install -y iproute2 build-essential make automake autoconf libtool",
    ]
  }

  # Cargo + Rust toolchain
  provisioner "shell" {
    inline = [
      "echo Installing rust toolchain and cargo",
      "curl https://sh.rustup.rs -sSf | sh -s -- -y",
      ". $HOME/.cargo/env",
      "rustup toolchain add nightly-2021-04-25",
      "rustup default nightly-2021-04-25",
      "rustup component add --toolchain nightly-2021-04-25 rustfmt clippy",
      "rustup update",
    ]
  }

  # Install test binary
  provisioner "shell" {
    inline = [
      "echo Installing abft binary",
      "ssh-keyscan ssh.dev.azure.com >> ~/.ssh/known_hosts",
      "git clone git@ssh.dev.azure.com:v3/henriknu/consensus-unstable-throughput/consensus-unstable-throughput",
      "cd consensus-unstable-throughput",
      ". $HOME/.cargo/env",
      "cargo build --release",
      "sudo chmod a+rx target/release/abft",
      "sudo cp target/release/abft /usr/local/bin",
    ]


  }


}