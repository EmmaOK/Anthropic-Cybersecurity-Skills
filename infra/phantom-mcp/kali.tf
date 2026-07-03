# Pentest execution backend for Phantom
#
# Ubuntu 22.04 LTS EC2 instance with pentest tools (nmap, nikto, masscan, gobuster,
# sqlmap, nuclei, hydra, etc.) installed on first boot via user_data.
# Phantom ECS tasks SSH to this instance to run commands that cannot execute in Fargate.
#
# NOTE: The SSH private key is stored in Terraform state (encrypted at rest via S3 backend).
# For a higher-security deployment, generate the key pair outside Terraform and import it.

# ── SSH Key Pair ───────────────────────────────────────────────────────────────

resource "tls_private_key" "kali" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "kali" {
  key_name   = "${local.name_prefix}-kali-${var.environment}"
  public_key = tls_private_key.kali.public_key_openssh
  tags       = local.common_tags
}

resource "aws_secretsmanager_secret" "kali_ssh_key" {
  name        = "${local.name_prefix}/${var.environment}/kali-ssh-private-key"
  description = "SSH private key (PEM) for Phantom ECS tasks to connect to the Kali pentest backend"
  tags        = local.common_tags
}

resource "aws_secretsmanager_secret_version" "kali_ssh_key" {
  secret_id     = aws_secretsmanager_secret.kali_ssh_key.id
  secret_string = tls_private_key.kali.private_key_pem
}

# ── Security Group ─────────────────────────────────────────────────────────────

resource "aws_security_group" "kali" {
  name        = "${local.name_prefix}-kali-${var.environment}"
  description = "Kali pentest backend - SSH from Phantom ECS tasks only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "SSH from Phantom ECS tasks"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  # Kali needs full outbound to reach external scan targets and download tool updates
  egress {
    description = "All outbound - tool downloads and external scan targets"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.name_prefix}-kali" })
}

# ── IAM (SSM patch management) ─────────────────────────────────────────────────

resource "aws_iam_role" "kali" {
  name = "${local.name_prefix}-kali-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "kali_ssm" {
  role       = aws_iam_role.kali.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "kali" {
  name = "${local.name_prefix}-kali-${var.environment}"
  role = aws_iam_role.kali.name
}

# ── AMI ────────────────────────────────────────────────────────────────────────

# Ubuntu 22.04 LTS — no Marketplace subscription required.
# All pentest tools are installed via user_data on first boot (~5 min).
data "aws_ami" "kali" {
  most_recent = true
  owners      = ["099720109477"] # Canonical official

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# ── EC2 Instance ───────────────────────────────────────────────────────────────

resource "aws_instance" "kali" {
  ami                    = data.aws_ami.kali.id
  instance_type          = var.kali_instance_type
  subnet_id              = var.private_subnet_ids[0]
  vpc_security_group_ids = [aws_security_group.kali.id]
  key_name               = aws_key_pair.kali.key_name
  iam_instance_profile   = aws_iam_instance_profile.kali.name

  root_block_device {
    volume_size = 50 # GB — tool databases (nuclei templates, seclists, wordlists) need space
    volume_type = "gp3"
    encrypted   = true
  }

  user_data = base64encode(<<-EOF
    #!/bin/bash
    set -e
    export DEBIAN_FRONTEND=noninteractive

    apt-get update -q
    apt-get install -y -q \
      nmap nikto masscan gobuster dirb \
      sqlmap hydra john hashcat \
      wfuzz whatweb sslscan \
      python3-pip python3-requests python3-scapy \
      curl wget jq git unzip 2>/dev/null || true

    # testssl.sh
    git clone --depth 1 https://github.com/drwetter/testssl.sh /opt/testssl 2>/dev/null || true
    ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

    # nuclei — fetch latest release, strip leading 'v' from version for filename
    NUCLEI_VER=$$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | jq -r .tag_name 2>/dev/null || echo "v3.3.9")
    NUCLEI_CLEAN=$$(echo "$${NUCLEI_VER}" | sed 's/^v//')
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/$${NUCLEI_VER}/nuclei_$${NUCLEI_CLEAN}_linux_amd64.zip" \
      -O /tmp/nuclei.zip \
      && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
      && chmod +x /usr/local/bin/nuclei || true

    # SecLists wordlists
    git clone --depth 1 https://github.com/danielmiessler/SecLists /usr/share/seclists 2>/dev/null || true

    # Update nuclei templates
    /usr/local/bin/nuclei -update-templates 2>/dev/null || true

    # Grant ubuntu user passwordless sudo for pentest tools
    echo "ubuntu ALL=(ALL) NOPASSWD: /usr/bin/nmap,/usr/bin/nikto,/usr/bin/masscan,/usr/bin/gobuster,/usr/bin/sqlmap,/usr/bin/hydra,/usr/bin/john,/usr/local/bin/nuclei" \
      > /etc/sudoers.d/ubuntu-pentest
    chmod 440 /etc/sudoers.d/ubuntu-pentest
  EOF
  )

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-kali-${var.environment}"
    Role = "pentest-backend"
  })

  lifecycle {
    # Don't replace instance when AMI updates — re-run terraform apply deliberately
    ignore_changes = [ami, user_data]
  }
}
