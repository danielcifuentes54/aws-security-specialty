<img src="icons/AWS-S.png" />

# AWS Security Specialty
Information about the AWS services that are required in the AWS Security Specialty certification.

## Optional Course

* AWS Security Fundamentals (Skill Builder) https://aws.amazon.com/es/training/digital/aws-security-fundamentals/

## Incident Response

### Amazon Guard Duty

* Intelligent threat discovery to protect your AWS account
* Input Data:
  * CloudTrail Events Logs
  * VPC flow logs
  * DNS Logs
  * Kubernetest Logs
* Can setup Eventbridge rules to be notified in case of findings
* Can protect against CryptoCurrency attacks
* Can setup Multi-account strategy in AWS Organizations
* Can setup Trusted and Threat IP List.

### AWS Security Hub

* Central security tool to manage security across several AWS accounts and automate security checks
* Automaticxally aggregates alerts in predifined or personal findings formats from various AWS services & AWS partner tools
* Can setup cross region aggregation
* Can setup AWS organizations Integrations
* AWS config must be enabled
* Generate findings and continoous chechs against the rules in a set of supported security standards
* Integrations (Send findings to AWS security hub):
  * AWS config
  * Firewall Manager
  * GuardDuty
  * AWS Health
  * IAM Access Analyzer
  * Inspector
  * IoT Device Defender
  * Macie
  * SSM Patch Manager
* Integrations (Receive findings from AWS security hub):
  * Audit Manager
  * AWS chatbot
  * Amazon Detective
  * Trusted Advisor
  * SSM Explorer and OpsCenter
* Custom Actions: helps you to automate Security Hub with Eventbridge
* Architecture:
  1. Detect (Security Hub)
  2. Ingest (Eventbridge)
  3. Remediate (Lambda, Step Functions)
  4. Log (SNS, CloudWatch)


### Amazon Detective

* Amazon Detective analyzes, invetigates, and quickly identifies **the root cause of security issues** or suspicious activities (using ML & graphs)
* Automatically collects and processes events from VPC flow logs, CloudTrail, GuardDuty and create aunified view

### Penetretion Testing on AWS Cloud

* You can carry out security assesments or penetretation tests against AWS without prior approval for 8 Services:
  1. Amazon EC2 instances, NAT gateways, load balancers
  2. Amazon RDS
  3. Amazon Cloudfront 
  4. Amazon Aurora
  5. Amazon Api Gateways
  6. Amazon Lambda and Lambda Edge functions
  7. Amazon Ligthsail resources
  8. Amazon Elastic Beanstalk environments

* There are also prohibited activities:
  * DNS zome walking
  * DDOS
  * Port flooding
  * protocol flooding
  * Request flooding

### Compromised AWS Resources

* EC2 Instance:
  * Steps to address compromised instances:
    * Capture instance metadata
    * Enable termination protection
    * Isolate the instance (no outbound traffic authorized)
    * Detach the instance from any ASG 
    * Deregister the instance from any ELB
    * Snapshot the EBS volumes
    * Tag the EC2 instance
* Investigations types:
  * offline investigation
  * online investigation

### Compromised AWS Credentials

* Identify the IAM user using GuardDuty
* Rotate the exposed AWS credentials
* Invalidate temporary credentials by **attaching an explicit Deny policy** to the affected IAM user with an STS date condition
* Check cloudtrail logs for other unauthorized activity
* Review your AWS resources (e.g. delete unauthorized resources)
* Verify your AWS account information

### EC2 Key Pairs

* The public key is stored in ~/.ssh/authorized_keys (on the EC2 instance)
* The private key is downloaded and then deleted from AWS
* Keys pairs do not get deleted from EC2 instance's root volumes when the key pair is removed from the EC2 console
* Launching an EC2 instance with prebuilt AMI, thje old key pair will exist alongside with the new key pair
* Remediating Exposed EC2 Key Pairs:
  * Remove all the public keys in ~/.ssh?authorized_keys on EC2 instances
  * Create a new key pair and add its public to the ~/.ssh/authorized_keys file on all EC2 instances
  * Note: Use a SSM run command to automate the process

### EC2 Instance Connect

* The EC2 instance connect API push one-time temporary public key (valid for 60 sec) on the instance metadata
* The EC2 instance connect API try the connection through SSH
* The EC2 instance checks the authorized_keys and also the instance metadata, so the connection is established
* NOTE: The Instance's Security group needs to allow the AWS IP range for the service "EC2 instance connect API" (NO the browser's public IP)

### EC2 Serial Console - Explanation

* Use cases: troubleshoot boot, troubleshoot network configuration, analyze reboot issues.
* Directly access you EC2 instance's serial port
* Use with supported Nitro-based EC2 instances
* Does NOT require any network capabilities
* Must setup OS User and password
* Only one session active per EC2 instance
* Disabled by default

### Lost EC2 Key Pair - Linux



---



##  Security in the AWS cloud

* Confidentiality
* Integrity
* Availability

- Visibility (AWS Config)
- Auditability (AWS CloudTrail)
- Controllability (AWS IAM)
- Agility (AWS CloudFormation)
- Automation (AWS CloudFormation)

## AWS Shared Responsability Model

* AWS is responsible for the security OF the cloud
* Customers are responsible for their security IN the cloud

- AWS Infrastructure Services
- AWS container Services 
- AWS Abstracted Services
- MSO responsability Model

## Incident Response Overview

* AWS Cloud Adoption Framework Security Perspective https://aws.amazon.com/es/professional-services/CAF/
* AWS well architected https://www.wellarchitectedlabs.com
  * AWS has a well architected tool

### Common Incidents

- Compromised User Credentials
- Insufficient data integrity
- Overlay Permissive Access

## DevOps With Security Engineering

* Penetration Testing https://aws.amazon.com/security/penetration-testing/
* https://aws.amazon.com/security/?nc=sn&loc=0

## AWS Entry Points

* AWS managment console
* AWS CLI
* AWS SDKs
* Another AWS Service

## STS

* It is used always when you use a role
* you can have sessions to limit access on the time
## IAM Policy Types

* AWS Managed 
* Customer Managed
* Inline

### Understanding IAM Policies

* [Policy Generator](https://awspolicygen.s3.amazonaws.com/policygen.html)

* Granting Access Review: 
  1. Authorization (identity-based policies + Resource-based Policies)
  2. Actions
  3. Resources
  4. Effect

* IAM Policy elements:
  1. Effect (mandatory)
  2. Action (mandatory)
  3. Resource (mandatory)
  4. [Condition](https://docs.aws.amazon.com/es_es/IAM/latest/UserGuide/reference_policies_elements_condition.html)
  5. Principal (only for resource based policies)

* [Attribute-based access control (ABAC)](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_attribute-based-access-control.html)

* IAM Access Analyzer: Service to monitoring resource access

* [Not Action](https://docs.aws.amazon.com/es_es/IAM/latest/UserGuide/reference_policies_elements_notaction.html)

### Permissions Boundary

*  A permissions boundary is an advanced feature for using a managed policy to set the maximum permissions that an identity-based policy can grant to an IAM entity

# Security Considerations: Web Applications

# Application Security

## Amazon EC2 Security Considerations

* Amazon EC2 Key Pairs
* Instance Metadata Service (IMDS) 
  * `curl http://169.254.169.254/latest/meta-data`

## AMI For Security and Compliance

* Incident response can use AMIs to spin up machines for forensics
* Customize AMIs via baking
* Customize AMIs via bootstrapping
* Protection:
  - Disable unsecure applications.
  - Miniize exposure.
  - Protect Credentials.
  - Protect system and log data.
  - Use EC2 image builder.

## Amazon Inspector

* Help to improve security and compliance of applications:
  - Automation of security assesments
  - Built-in library of AWS security knowledge and best practices 
  - Guidance on resolving security findings

## AWS Sytems Manager

* System Inventory
* OS patches updates
* Automated AMI creation
* OS and application configuration
* Session Manager

# Data Security

* Threats in Data Protection:
  - Information Disclosure
  - Data Integrity Compromise
  - Accidental Deletion
  - System/HW/SW Availability

## Protecting Data at rest: S3

* Data Encryption on S3:
  - SSE-C
  - SSE-S3
  - SSE-KMS
* Amazon S3 Resource Protection:
  - Object ACLs
  - Bucket ACLs
  - Bucket Policies
  - IAM Policies
* Amazon S3 Versioning
* Amazon S3 Object Lock
* Amazon S3 - Block public access
* Cross-Region Replication
* AWS S3 Access Analyzer
* AWs S3 Access Points

## Protecting Data at rest: Databases

* Amazon RDS Protection:
  * Network Isolation
  * Access Control
  * Data Protection:
    * In Transit
    * At Rest

* DynamoDB