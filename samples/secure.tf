provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "student_data" {
  bucket = "somaiya-student-data"
  acl    = "private"
  tags   = { Owner = "tanush", Environment = "lab" }
}

resource "aws_security_group" "web_sg" {
  name = "web-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  tags = { Owner = "tanush", Environment = "lab" }
}

resource "aws_ebs_volume" "app_disk" {
  availability_zone = "ap-south-1a"
  size              = 20
  encrypted         = true
  tags              = { Owner = "tanush", Environment = "lab" }
}

resource "aws_db_instance" "main_db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  tags                = { Owner = "tanush", Environment = "lab" }
}

resource "aws_iam_policy" "s3_read_only" {
  name   = "s3-read-only"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::somaiya-student-data/*" }]
  })
}
