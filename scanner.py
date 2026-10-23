"""CloudGuard rules engine: scans Terraform (HCL) code for cloud security misconfigurations."""
import re

RESOURCE_RE = re.compile(r'resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{')
PENALTY = {"HIGH": 15, "MEDIUM": 8, "LOW": 3}
TAGGABLE = {"aws_s3_bucket", "aws_instance", "aws_ebs_volume", "aws_db_instance",
            "aws_security_group", "aws_vpc", "aws_lambda_function"}


def _blocks(code):
    """Return a list of (type, name, body, line_no) for every resource block."""
    out = []
    for m in RESOURCE_RE.finditer(code):
        depth, i = 1, m.end()
        while i < len(code) and depth:
            depth += {"{": 1, "}": -1}.get(code[i], 0)
            i += 1
        line = code.count("\n", 0, m.start()) + 1
        out.append((m.group(1), m.group(2), code[m.end():i - 1], line))
    return out


def _sub_blocks(body, keyword):
    """Return the inner text of nested blocks such as ingress { ... }."""
    res = []
    for m in re.finditer(rf'\b{keyword}\s*\{{', body):
        depth, i = 1, m.end()
        while i < len(body) and depth:
            depth += {"{": 1, "}": -1}.get(body[i], 0)
            i += 1
        res.append(body[m.end():i - 1])
    return res


def _attr(body, key):
    m = re.search(rf'^\s*{key}\s*=\s*"?([^"\n]+?)"?\s*$', body, re.M)
    return m.group(1).strip() if m else None


def _f(sev, rule, res, line, msg, fix):
    return {"severity": sev, "rule": rule, "resource": res, "line": line,
            "message": msg, "fix": fix}


def scan(code):
    findings = []
    for rtype, name, body, line in _blocks(code):
        res = f"{rtype}.{name}"

        # CG001 Public S3 bucket
        if rtype in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            acl = _attr(body, "acl")
            if acl in ("public-read", "public-read-write"):
                findings.append(_f("HIGH", "CG001", res, line,
                                   f"S3 bucket is public (acl = {acl}).",
                                   'Set acl = "private" and enable S3 Block Public Access.'))

        # CG002 / CG003 Security group open to the internet
        if rtype == "aws_security_group":
            for ing in _sub_blocks(body, "ingress"):
                if "0.0.0.0/0" not in ing:
                    continue
                fp = int(_attr(ing, "from_port") or 0)
                tp = int(_attr(ing, "to_port") or fp)
                risky = [p for p in (22, 3389) if fp <= p <= tp]
                if risky:
                    findings.append(_f("HIGH", "CG002", res, line,
                                       f"Admin port {risky[0]} open to 0.0.0.0/0.",
                                       "Restrict cidr_blocks to your office/VPN IP or use SSM Session Manager."))
                elif not (fp == tp and fp in (80, 443)):
                    findings.append(_f("MEDIUM", "CG003", res, line,
                                       f"Ports {fp}-{tp} open to 0.0.0.0/0.",
                                       "Only expose 80/443 publicly; restrict everything else."))

        # CG004 Unencrypted EBS volume
        if rtype == "aws_ebs_volume" and _attr(body, "encrypted") != "true":
            findings.append(_f("HIGH", "CG004", res, line,
                               "EBS volume is not encrypted at rest.",
                               "Add encrypted = true (optionally a kms_key_id)."))

        # CG005 / CG006 RDS checks
        if rtype == "aws_db_instance":
            if _attr(body, "storage_encrypted") != "true":
                findings.append(_f("HIGH", "CG005", res, line,
                                   "RDS storage is not encrypted.",
                                   "Add storage_encrypted = true."))
            if _attr(body, "publicly_accessible") == "true":
                findings.append(_f("HIGH", "CG006", res, line,
                                   "RDS instance is publicly accessible.",
                                   "Set publicly_accessible = false and keep it in a private subnet."))

        # CG007 Wildcard IAM permissions
        if rtype.startswith("aws_iam") and re.search(r'"?Action"?\s*[=:]\s*\[?\s*"\*"', body):
            findings.append(_f("HIGH", "CG007", res, line,
                               'IAM policy allows all actions ("*").',
                               "Follow least privilege: list only the actions needed."))

        # CG008 Hard-coded secrets
        for key in ("password", "secret_key", "access_key"):
            val = _attr(body, key)
            if val and not val.startswith(("var.", "data.", "${", "aws_", "random_")):
                findings.append(_f("HIGH", "CG008", res, line,
                                   f"Hard-coded secret in '{key}'.",
                                   "Use a variable marked sensitive or AWS Secrets Manager."))

        # CG009 Missing tags
        if rtype in TAGGABLE and not re.search(r'^\s*tags\s*=', body, re.M):
            findings.append(_f("LOW", "CG009", res, line,
                               "Resource has no tags (cost tracking / ownership).",
                               'Add tags = { Owner = "...", Environment = "..." }.'))

    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda x: (order[x["severity"]], x["line"]))
    score = max(0, 100 - sum(PENALTY[f["severity"]] for f in findings))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 50 else "F"
    counts = {s: sum(f["severity"] == s for f in findings) for s in PENALTY}
    return {"score": score, "grade": grade, "counts": counts, "findings": findings,
            "resources": len(_blocks(code))}
