provider "aws" {
  region = "ap-south-1"
}

resource "aws_s3_bucket" "student_data" {
  bucket = "somaiya-student-data"
  acl    = "public-read"
}

resource "aws_security_group" "web_sg" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ebs_volume" "app_disk" {
  availability_zone = "ap-south-1a"
  size              = 20
}

resource "aws_db_instance" "main_db" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "SuperSecret123"
  publicly_accessible = true
}

resource "aws_iam_policy" "admin_all" {
  name   = "admin-all"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
