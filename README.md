<img src="icons/AWS-S.png" />

# AWS Security Specialty
Information about the AWS services that are required in the AWS Security Specialty certification.

## Optional Course

* AWS Security Fundamentals (Skill Builder) https://aws.amazon.com/es/training/digital/aws-security-fundamentals/

## Threat Detection and Incident Response

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
* Automatically aggregates alerts in predifined or personal findings formats from various AWS services & AWS partner tools
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
  * Amazon Inspector
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
* Launching an EC2 instance with prebuilt AMI, the old key pair will exist alongside with the new key pair
* Remediating Exposed EC2 Key Pairs:
  * Remove all the public keys in ~/.ssh/authorized_keys on EC2 instances
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

* Add a new ssh public key using EC2 User Data.
* Using systems manager (AWSSupport_resetAccess). Must have SSM agent installed.
* Using EC2 instance connect (store a permanent new public SSH key into ~/.ssh/authorized_keys).
* Using EC2 serial console (store a permanent new public SSH key into ~/.ssh/authorized_keys).
* Using EBS volume swap (Attach the EBS volume to a temporary EC2 instance as a secondary volume to store a permanent new public SSH key into ~/.ssh/authorized_keys).

### Lost Password - Windows

* Using EBS volume swap and delete the file located in %ProgramData%/Amazon/EC2Launch/state/.run-once if the AMI is before windows server 2016 you have to modify the file located in \ProgramFiles\Amazon\Ec2ConfigService\settings\config.xml.
* Using EBS volume swap and install EC2Rescue Tools for windows server.
* Using system manager with AWSSupport-RunEc2RescueForWindowsTools. AWSSupport-ResetAccess, or AWS-RunPowerShellScript command document

### EC2 Rescue Tool

* Linux:
  * installation: manually or using AWSSupport-TroubleshootSSH
  * use cases:
    * Collect system utilization reports
    * Collect logs and details
    * Detect system problems
    * Automatically remediate system problems
* Windows:
  * installation: manually or using AWSSupport-RunEc2RescueForWindowsTools
  * use cases:
    * Instance connectivity issues
    * OS Boot issues
    * Gather OS logs and configuration Files
    * commom OS issues
    * perform a restore

### AWS Acceptable Use Policy (AUP)

* Governs your use of the services offeredd by AWS
* You may not use for:
  * :no_entry_sign: Illegal or fraudelent activity.
  * :no_entry_sign: Violate the rights of others.
  * :no_entry_sign: Threaten, terrorism, violence, or other serious harm.
  * :no_entry_sign: Child sexual abuse content or activity.
  * :no_entry_sign: Violate the security, integrity or availability for other networks and computers.
  * :no_entry_sign: Distribute, publish or facilitate the unsolicited mass emails (e.g. spams).
* AWS will remove or disable any content that violates this policy.

### AWS Abuse Report

* When you suspect that AWS resources are used for abusive or illegal purposes, you can create an abuse report, contact **AWS Trust & Safety Team**
* if you recceive an email that your AWS resources are used for illegal activity, respond to the email and explain how you're preventing this, if you don't respond within 24 hours, AWS might suspend your AWS account.

## Security Logging and monitoring

### Amazon Inspector

* Automated Security Assesments:
  * For EC2 instances
  * For container images push to Amazon ECR
  * For Lambda functions
* Reporting & integration with AWS Security hub
* Send findings to Amazon Event Bridge
* Package vulnerabilities (EC2, ECR & Lambda) - database of CVE
* Newtwork reachability (EC2)
* A risk score is associated with all vulnerabilities for prioritization 

### Logging in AWS

* Service logs:
  * CloudTrail trails
  * Config rules
  * CloudWatch logs
  * VPC flow logs
  * ELB access logs
  * Cloudfront logs
  * WAF logs
* Logs can be analyzed using AWS Athena if they're stored in S3


### AWS Systems Manager Overview

* Helps you manage your EC2 and on-premises system at scale
* Easily detect problems 
* Patching automation for enhanced compliance
* Free service
* We need to install the SSM agent onto the systems we control (installed by default on Amazon linux 2 AMI & some Ubuntu AMI), an SG rule is not neccesary
* Resource Groups: Create, view or manage logical group of resources thanks to **tags**
* SSM Documents: you can define actions and parameters to be executed in an EC2 instance, the document can be in JSON or YAML
* SSM Automation: 
  * Simplifies commom maintenance and deployment tasks of EC2 instances and other AWS resources
  * it uses automation runbook: SSM documents of type automation
  * Can be triggered:
    * manually (AWS console), SDK, CLI
    * Eventbridge
    * On a schedule using Maintenance windows
    * By AWS Config for rules remediations
* SSM Parameter Store:
  * Secure storage for configuration and secrets 
  * It has a store hierarchy and you can get a secret from there
    * /aws/reference/secretsmmanager/SECRET_ID
  * Advanced parameters allows to assign parameters policies like a TTL (expiration date)
* SSM Inventory & State Manager
  * Collect data from your managed instances (EC2 / On Premises).
  * Query data from multiple AWS accounts and regions.
  * You can use a detailed view, where you will use AWS Athena, AWS Glue, and S3 to store and query data in a very specific way.
  * State manager is to ensure that you fleet of instances are all in a state that you desire.
* SSM Patch Manager
  * Automated the process of patching managed instances
  * Patch compliance report cacn be sent to S3
  * You can setup a maintenance window to define a schedule for when to performm actions on your instances
* Session Manager
  * Allow to start a secure shell on you EC2 instance 
  * Does not need SSH acces, bastion hosts, or SSH keys
  * Log connections and executed commands
  * IAM Permissions: control which users/groups can access session manager and which instances, use tags to restrict access to only specific EC2 instances, optionally, you can restrict commands a user can run in a session

### CloudWatch

* Unified CloudWatch Agent:
  * Collect logs to send to CloudWatch logs 
  * Collect additional system-level metrics such as RAM, processes, used disk space, etc. (Default namespace for metrics is **CWAgent**)
  * The agent has a plugin call procstat plugin that collect metrcis and monitor system utilization of individual processes (e.g amount of time the process use CPU), Metrics collected by procstat plugin bgin with **procstat** prefix
  * Path to check cloudwatch unified agent logs: /opt/aws/amazon-cloudwatch-agent/logs

* Cloud Watch Logs:
  * Log Groups: Representing an application
  * Log Stream: Representing an instance or container
  * Can define expiration policies
  * Logs can be send to:
    * Amazon S3 (Batch export, )
    * Kinesis Data Streams
    * Kinesis Data Firehouse
    * AWS Lambda
    * Opensearch
  * Logs are encrypted by default
  * Sources:
    * SDK, cloudwatch agent (unified and logs(deprecated))
    * Elastic Beanstalk
    * ECS
    * AWS Lambda
    * VPC Flow Logs
    * API gateway
    * Cloud Trail
    * Route53
  * CloudWatch Logs Insights: 
    * Search and analyze log data stored in CloudWatch Logs
    * It's a query engine, not a real-time engine
  * CloudWatch Logs Subscriptions: You can filter wich logs are delivered to Lambda (then to opensearch) or kinesis (Data Streams or Data fire house), this is use to get real-time logs events.

* CloudWatch Alarms
  * Used to trigger notifications for any metric
  * States:
    * OK
    * INSUFFICIENT_DATA
    * ALARM
  * Period: Length of time in seconds to evaluate the metric
  * Targets: EC2 instance action, EC2 autoscaling, SNS, Systems Manager action
  * Composite Alarms: Monitoring the states of multiple alarms using AND and OR conditions, it's helpful to reduce "alarm noise" 
  * Alarms can be created based on CloudWatch Logs Metrics Filter

* CloudWatch Contributor Insights: Helps you find top talkers and understand who/what is impacting system performance

### Amazon EventBridge (Formerly CloudWatch Events)

* Sources
  * Schedule: Cron jobs (scheduled scripts) --> Default Event Bus
  * Event Pattern from an AWS services --> Default Event Bus
  * AWS SaaS partner --> Partner Event Bus
  * Custom Apps --> Custom Event Bus
* Schemas: Defines the structure and content of events that are passed on an event bus in Amazon EventBridge, you can download code bindings

### Amazon Athena

* Serverless query service to analyze data stored in Amazon S3
* Use standar SQL language to query the files (built on Presto (SQL Engine))
* Commonly used with Amazon Quicksight for reporting/dashboards
* Performance Improvement:
  * Use columnar data for cost-savings (less scan)
    * Apache Parquet or ORC is recommended
    * use Amazon Glue to convert your data to Parquet or ORC
  * Compress Data
  * Partition dataset in S3 --> s3://athena-example/flight/parquet/year=1991/month=1/day=1/
  * Use larger files (> 128 MB)
* Federated Query: using a data source connector on lambda you can connect to different services like RDS, ElasticCache, Redshift, etc to run SQL queries and store the result on Amazon S3


### AWS CloudTrail

* Provides governance, compliance and audit for your AWS account.
* Cloud Trail Events:
  * Managment Events
  * Data Events
  * CloudTrail Insights Events --> Analyze events to try to find anomalies
* All the cloud trail events can be send to EventBridge (cloud trail is not real time)
* Log file integrity validation: you can create a digest file when you save the logs on S3, this digest file contains the hash for each log file
* Organization Trails: A trail that will log all events for all AWS accounts in an AWS organization.
* You can create alarms, using CloudWatch logs where are hosted all the cloud trail events
* You can create an Athena table directly from CloudTrail


### Amazon Macie

* Helps to identify and alert you to sensitive data, such as personally identifiable information (PII)
* Multi Account Strategy
* Data identifiers:
  * Managed Data Identifier: built-in, ex: credit card numbers, AWS credentials, bank accounts
  * Custom Data Identifier: you define the criteria with a regex, keyword, proximity rule (you also can have an allowed alist)
* Findings:
  * A report of potential issue or sensitive data that Macie found, each finding has a severity rating, affected resource, datetime...
  * it is stored for 90 days, or it can be stored in S3
  * it can be reviewed using AWS console, EventBridge, or security hub.
  * Types:
    * Policy Findings
    * Sensitive Data Findings

### S3 Event Notifications

* You can react events happening in S3
* Event notifications: S3:ObjectCreated, S3:Replication...
* You can create as many S3 events as desired, this events are delivered to SNS, SQS, Lambda, or EventBridge (all the events are sent to eventbridge)
* IAM Permissions: you need to create a resource policy in the destination side to enable S3 send the events

### VPC Flow logs

* Capture information about IP traffic going into your interfaces (VPC, Subnet, or Elastic Network Interface (ENI)), also from AWS managed interfaces: ELB, RDS, ElastiCache, Redshift...
* Flow logs data can be sent to S3, CW logs, and Kinesis Data Firehose.
* VPC Flow Logs Architectures:
  * Sent to CW logs --> CW contributor insights --> Top 10 Ip addresses
  * Sent to CW logs --> Metric Filter --> CW Alarm --> Amazon SNS
  * Sent to S3 bucket --> Amazon Athena --> Amazon QuickSight
* Traffic not captures:
  * Traffic to Amazon DNS server
  * Traffic for Amazon Windows license activation
  * Traffic to and from 169.254.169.254 for EC2 instance metadata
  * Traffic to and from 169.254.169.123 for Amazon time sync service
  * DHCP Traffic
  * Mirrored Traffic
  * Traffic to the VPC router reserved IP address (e.g 10.0.0.1)
  * Traffic between VPC endpoint ENI and Network Load Balancer ENI








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