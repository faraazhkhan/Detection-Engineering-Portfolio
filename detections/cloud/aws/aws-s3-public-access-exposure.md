# AWS S3 Public Access Block Removed or Bucket ACL Opened to Everyone or Any AWS Account

| | |
|---|---|
| **MITRE ATT&CK** | T1530 |
| **Tactic** | Collection |
| **Severity** | High |
| **Log source** | AWS CloudTrail management events (S3 bucket-level APIs) |
| **Required fields** | eventSource, eventName, requestParameters, userIdentity, sourceIPAddress |
| **Rule file** | [`aws-s3-public-access-exposure.yml`](./aws-s3-public-access-exposure.yml) |
| **Status** | Draft. Not yet validated in a lab. |

## What it detects
Detects changes that can expose an S3 bucket to the internet: deleting the public access block, or setting a bucket ACL that grants access to all users.

## Detection logic
Either of:
- An S3 `DeleteBucketPublicAccessBlock` call, which removes a bucket's protection against public access.
- An S3 `PutBucketAcl` call whose parameters grant access to `AllUsers` (anyone on the internet) or `AuthenticatedUsers` (any AWS account holder, which is almost as open because anyone can create an AWS account).

## How to test
In a personal sandbox AWS account, create a test bucket and run `aws s3api delete-public-access-block --bucket <name>`. Delete the bucket afterwards. Do not use real data.

Once validated, record the date, the tool used, and a sample of the matching event in the results section below.

## Expected false positives and tuning
- Buckets that intentionally host public content, such as a static website.
- Planned configuration changes by the platform team.

Maintain a list of buckets that are intentionally public and suppress them. Treat any other hit as a possible data exposure.

## Limitations
Bucket policies with a wildcard principal are not covered by this rule. ATT&CK has no exact technique for exposure, so T1530 is an approximate mapping. Account-level S3 Block Public Access settings are a better preventive control.

Other ways to expose a bucket are not covered, and the write-up is clear about that boundary:
- `PutBucketPolicy` with a wildcard principal (`"Principal": "*"`).
- Weakening block settings with `PutBucketPublicAccessBlock` or the account-level `PutPublicAccessBlock` (turning `BlockPublicAcls` or `RestrictPublicBuckets` off), or removing the account-level block.
These depend on matching nested policy or configuration JSON, which varies by SIEM, so they fit better in separate rules once you know how your pipeline stores that text.

## Validation results
_Not yet run._

## References
- https://attack.mitre.org/techniques/T1530/
