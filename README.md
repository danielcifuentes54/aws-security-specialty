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
* Generate findings and continous chechs against the rules in a set of supported security standards
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
  7. Amazon Lightsail resources
  8. Amazon Elastic Beanstalk environments

* There are also prohibited activities:
  * DNS zone walking
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
  * Patch compliance report can be sent to S3
  * You can setup a maintenance window to define a schedule for when to performm actions on your instances
* Session Manager
  * Allow to start a secure shell on you EC2 instance 
  * Does not need SSH access, bastion hosts, or SSH keys
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
    * Amazon S3 (Batch export)
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
    * Apache Parquet or ORC (Optimized Row Columnar) is recommended
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
* Uncaptured Traffic:
  * Traffic to Amazon DNS server
  * Traffic for Amazon Windows license activation
  * Traffic to and from 169.254.169.254 for EC2 instance metadata
  * Traffic to and from 169.254.169.123 for Amazon time sync service
  * DHCP Traffic
  * Mirrored Traffic
  * Traffic to the VPC router reserved IP address (e.g 10.0.0.1)
  * Traffic between VPC endpoint ENI and Network Load Balancer ENI

### VPC Traffic Mirroring

* Allows you to capture and inspect network traffic in your VPC, routing the traffic to security appliances that you manage
* Capture all the packets or capture the packets of your interest
* Uses cases: content inspection, threat monitoring, troubleshooting
* You can use VPC peering to send data across VPC's

### VPC Network Access Analyzer

* Helps to define conditions to check if the network meet your requirements
* Network Access Scope: Json document that contains conditions to define your network security policy (e.g detect public databases).
* Evaluate against the Json to find issues or demostrate compliance

### Route53 DNS Query Loggin

* Log information about public DNS queries Route53 Resolver receives
* only for public hosted zones
* Logs are sent to Cloudwatch logs only

### Route53 - Resolver Query Loggin

* Logs all DNS queries
* Can send logs to CloudWatch Logs, S3 Bucket, and Kinesis Data Firehose
* Configurations can be shared with other AWS accounts using AWS Resource Manager (AWS RAM)

### Amazon OpenSearch Service

* Search any field, even partially matches, it is common use opensearch as a complement to another database
* Two modes: managed cluster or serverless cluster
* Security through Cognito & IAM, KMS encryption, TLS
* Public Access: accesible from the internet, restrict access using Access Policies, Identity-based Policies, and Ip-based Policies
* VPC Access: Specify VPC, Subnets, Security Groups, and IAM Role for the cluster, you need to use VPN, Transit Gateway, managed network, or proxy server to connect to the domain, you can restric access using Access Policies and identity-based policies


## Infrastructure Security

### Bastion Host

* The bastion is an EC2 instance in the public subnet which is then connected to all other private subnets
* Bastion host SG must allow inbound from the internet on port 22 from restricted CIDR, for example, the public CIDR of your corporation

### Site to Site VPN

* It is a connection between on-premises infrastructure and an AWS VPC, this connection is made through the public internet in an encrypted way.
* Elements:
  * Virtual Private Gateway (VGW): created and attached to the VPC
  * Customer Gateway (CGW): Software application or physical device on customer side of the VPN connection (you need to use the public ip or if it is behind a NAT you must use de NAT public IP)
* Important Step: You must enable route propagation for the VGW in the route table that is associated with your subnets
* If you need ping your EC2 instances from on-premises, make sure you add the ICMP protocol in the inbound of your security groups

### AWS Client VPN

* Connect from your computer using OpenVPN to your private network in AWS and on-premises
* Authentication types:
  * Active Directory (Microsoft)
  * Mutual Authentication (certificates)
  * Single Sign on (SAML 2.0)

### VPC Peering

* Privately connect two VPCs using AWS's network
* Must not have overlaping CIDRs
* VPC peering connection is not transitive
* You must update route tables in each VPC's subnets to ensure EC2 instances can communicate with each other
* You can create VPC peerings between different AWS accounts/regions
* You can reference a security group in a peered VPC

### DNS Resolution options

* DNS Resolution in VPC:
  * DNS Resolution (enableDnsSupport): Route53 DNS resolver, it queries the amazon provider DNS server at 169.254.169.253 true by default. if you don't have DNS support you need your own DNS server.
  * DNS Hostname (enableDnsHostnames):
    * By default it is true in default VPC and false in a new created VPC
    * Won't do anything unless enableDnsSupport = true
    * if true, assings public hostname to EC2 instance 
  * if you use custom DNS domain names in a private hosted zone in R53, you must set both attributes (enableDnsSupport, & enableDnsHostnames) to true

### VPC Endpoints

* Endpoints allow you to connect to AWS services using a private network instead of the public www network, they sacale horizontally and are redundant
* Types:
  * VPC endpoint gateway (S3 & DynamoDB):
    * Must create one gateway per VPC
    * Must update route tables entries (no security groups)
  * VPC endpoint interface (all except DynamoDB)
    * Provision an ENI that will have a private endpoint interafce hostname.
    * Leverage Security Groups for security
    * Interface can be accessed from Direct Connect and Site-to-site VPN

### VPC Endpoint Policy

* Controls which AWS principals (AWS accounts, IAM Users, IAM Roles) can use the VPC Endpoint to acccess AWS services.
* Can restrict specific API calls on specific resources.
* Does not override or replace Identity-based policies or service-specific policies.
* Can be attached to both Interface Endpoint and Gateway Endpoint.
* Use case: have an SQS queue that must allow only requests from an specific VPC Endpoint and the VPC Endoint must allow only requests from an specific PrincipalOrgId

### PrivateLink (VPC Endpoint Service)

* Exposing services in your VPC to other VPC.
* Most secure & scalable way to expose a service to 1000s of VPC (own or other accounts).
* Requires a network load balancer (service VPC) and ENI (Customer VPC) or GWLB.
* the solutions can be fault tolerant (multiple AZ).

### Security Groups & NACLs

* NACLs (stateless): Evaluate both inbound and outbound for each transaction.
  * Are like firewall which control traffic from and to subnets
  * One NACL per subnet, new subnets are assigned the Default NACL
  * You define NACL rules (Rules have a number 1-32766 higher precedence with a lower number)
  * Newly created NACLs will deny everything
  * In news NACLs you have to be carefull in allowing **Ephemeral Ports**
* Security Groups (stateful): Evaluate inbound/outbound based on transaction direction.
  * Operates at the instance level
  * All rules are evaluated before deciding whether to allow traffic.
  * You can use **Managed Prefix List**
* Modifying Security Group Rule **NEVER** disrupts its tracked connections, existing connections are kept until they time out, you must use NACLs to interrupt/block connections immediately

>Notes:
>
>Ephemeral Ports: For any two endpoints to establish a connection, they must use a ports, the endpoint that send the request also send a ephemeral port (random port, different OS use different por ranges) to receive the response.
>
>AWS Managed Prefix Lists are predefined sets of IP address ranges used for controlling traffic routing and security group rules. They simplify network management by providing consistent and frequently updated IP ranges for services like AWS services and public AWS endpoints.

### AWS Transit Gateway

* For having transitive peering between thousands of VPC and on-premises, hub-and-spoke (star) connection.
* Regional resource, can work cross-region
* Share cross-account (RAM)
* you can peer transit gateway across regions
* Route tables: limit which VPC can tal with other VPC
* Works with Direct Connect, VPN Connections
* Supports **IP Multicast** (not supported by any other AWS Service)
* Site to site VPN **ECMP (Equal cost multi-path routing)** 
  * Create multiple site-to-site VPN connections to increase the bandwitch of you connections to AWS.
* You can share transit gateway with direct connect 

### AWS Cloudfront (CDN - Content Delivery Network)

* 216 Point of presence globally (edge locations), improves user experience, improving read performance, content is chached at the edge.
* DDoS protection (because worlwide) integration with shield, and WAF
* Origins:
  * S3 bucket
  * Custom origin http (ALB, EC2 instance, S3 website, Any http backend)
* Great for **static** content that must be available everywhere.
* You can have Geo Restriction
* Signed:
  * Useful if you want to distribute paid content to premium users over the world
  * Signers:
    * An AWS account that contains CloudFront Key Pair (Not recommended)
    * Trusted Group (Recommended): Can leverage APIs to create and rotate keys (and IAM for API Security)
  * types:
    * URL
      * one signed url per files
    * Cookie
      * one signed cookie for multiple files
* Field Level Encryption: Adds addtional layer of security along with https using asymetric encryption (client encrypt with the public key and the backend server decrypt with the private key)
* Origin Access Control: supports SSE-KMS natively
* Authorization Header: configure cloudfront distribution to forward the Authorization header using cache policy (not supported for s3 origins)
* Restrict access to ALB: have a **private custom header** to prevent direct access to your ELB (only access through CloudFront)
  * You can also use SG on the ALB to allow only requests coming from CloudFront
* Integration with Cognito: Use cognito to generate JWT and Lambda@Edge to validate those token and allow access to cloudfront


### WAF (Web Application Firewall)

* Protect your web applications from commom web exploits (Layer 7)
* You can use it in: ALB, API Gateway, CloudFront, Appsync (protect GraphQL APIs)
* WAF **is not** for DDoS protection.
* Define Web ACL (Access Control List)
* Rule Actions: Count | Allow | Block | CAPTCHA
* Managed Rules: Library of over 190 managed rules, ready to use, these are managed by AWS and AWS maketplace sellers
* Types: Baseline Rule Groups, Use-case Specific Rule Groups, IP Reputation Rule Groups, Bot Control Managed Rules
* Logging: ClodWatch Logs, Amazon S3, Kinesis Data Firehose
* You can create IP sets to be used in a managed rule

### AWS Shield 

* Protect from DDoS attack
* AWS Shield Standard:
  * Free service that provides protection from attacks such as SYN/UDP Floods, Reflection atacks and other layer 3/layer 4 attacks.
* AWS Shield Advance
  * $3000 per month per organization
  * Protect against more sophisticated attack: EC2, ELB, CloudFront, AWS Global Accelerator, and route53
  * 24/7 access to AWS DDoS response team (DRP)
  * Automatic Application layer DDoS mitigation automatically creates, evaluates and deploys AWS WAF rules to mitigate layer 7 attacks.
  * CloudWatch Metrics:
    * DDoSDetected
    * DDoSAttackBitsPerSecond
    * DDoSAttackPacketsPerSecond
    * DDoSAttackRequestPerSecond

### AWS Firewall Manager

* Manage rules in all accounts of an AWS organization
* Security Policy: common set of security rules
  * WAF rules
  * Shield advance rules
  * Security Groups
  * AWS Network Firewall
  * Amazon Route 53 Resolver
  * Policies are created at the region level
* Rules are applied to new resources as they are created

### AWS API Gateway

* Is used to expose our services to the clients, it has a lot of features like caching, rate limit, versioning, authentication, and others.
* Endpoints Types:
  * Edge-Optimized
  * Regional
  * Private
* Security:
  * User Authentication:
    * IAM Roles
    * Cognito
    * Custom Authorizer
  * Customm domain name HTTPS
  * Resource Policy
    * Restric access from specific public IP addresses
    * Restric access from specific VPC Endpoints
  * Cross VPC same-region access: VPC Interface Endpoint (restric from specific vpc interface endpoint)

### AWS Artifact (not really a service)

* It is not a service, it is a way to have access to AWS compliance documentation and AWS agreements
* Artifact Reports: compliance documents from third-party auditors
* Artifact Agreements: Status of AWS agreements

### Route53 - DNS Security Extensions (DNSSEC)

* It helps to mitigate DNS spoofing (Injection of a record in the local DNS server).
* Works only with Public Hosted Zone.
* Validate that a DNS response came from Route53 and has not been tampered with
* Route53 Cryptographically signs each recod in the hosted zone
* Keys can be created:
  * Managed by you: Key-signing key (KSK)
  * Managed by AWS: Zone-Signing Key (ZSK)
* Enforces a TTL of one week (Max).
* Enable DNSSEC on a hosted zone:
  * Step 1 - prepare for DNSSEC signing (Lower TTL and SOA)
  * Step 2 - Enable DNSSEC signing and create a KSK
  * Step 3 - Establish chain of trust
  * Step 4 - Monitoring --> Cloud Watch alarms: DNSSECInternalFailure and DNSSECKey SigningKeysNeedingAction

### AWS Network Firewall

* Protect your entire Amazon VPC from layer 3 to layer 7
* you can inspect in any direction
* Internally uses the AWS Gateway Load Balancer
* Rules can be centrally manageed cross-account by AWS Firewall Manager to apply to many VPCs
Supports 1000s of rules
* Traffic filtering
* Send logs of rule matches to Amazon S3, CloudWatch Logs, Kinesis Data Firehose

### AWS SES

* Fully managed service to send emails securely, globally and at scale.
* Allows inbound/outbound emails.
* Support DKIM and SPF
* Configuration Sets (to customize and analyze your emails send events)
  * Event destinations:
    * Kinesis Data Firehouse
    * SNS
  * IP pool management

## Identity and Access Management

### IAM Policies in Depth

* IAM Policies Structure:
  * Version > Policy Language Version (always 2012-10-17)
  * Id > Policy Identifier (Optional)
  * Statement > Array with one or more statements
    * Sid > Statement identifier (optional)
    * Effect > Allow or Deny access
    * Principal > Account/user/role to which this policy applied to
    * Action > List of actions this policy allows or deny
    * Resource > List of resources to which the actions applied to
    * Condition > Conditions for when this Policy is in effect (optional)
* NotAction: Provide access to all the actions in an AWS service, except for the actions specified in NotAction
* NotAction with Effect> Deny: Deny access to all the listed resources except for the actions specified in the NotAction
```json
{
  "Effect": "Deny",
  "NotAction": "iam:*",
  "Resource": "*"
  ...
}
in this example the policy will deny access to all resources except IAM 
```
* Action | not action & Allow | Deny:
```json
{
  "Effect": "Allow",
  "Action": ["iam:*"],
  "Resource": "*"
  ...
}

Allows IAM
```

```json
{
  "Effect": "Deny",
  "Action": ["iam:*"],
  "Resource": "*"
  ...
}
Deny IAM
```

```json
{
  "Effect": "Allow",
  "NotAction": ["iam:*"],
  "Resource": "*"
  ...
}
Allow everything but IAM
```

```json
{
  "Effect": "Deny",
  "NotAction": ["iam:*"],
  "Resource": "*"
  ...
}
Deny Everything but IAM
```
* Principal Options:
  * AWS Account and Root User
  * IAM Roles
  * IAM Roles Sessions
  * IAM Users
  * Federated User Sessions
  * AWS Services
  * All principals (```"principal": "*", "principal": "{"aws":"*"}"```)

* IAM Condition - Condition Operators
  * StringEquals / StringNotEquals
  * StringLike / StringNotLike
  * DateEquals / DateLessThan / DateGreaterThan
  * ArnLike / ArnNotLike
  * Bool
  * IpAddress / NotIpAddress
  
* IAM Condition - Global Conditions:
  * RequestedRegion
  * PrincipalArn
  * SourceArn (Service to Service request)
  * CalledVia (athena, cloudformation, dynamodb, kms)
  * SourceIp
  * VpcSourceIp
  * SourceVpce
  * SourceVpc
  * ResourceTag 
  * PrincipalTag

* IAM Permission Boundaries
  * Supported for users and roles (not groups).
  * Advanced feature to use a managed policy to set maximum permissions an IAM entity can get.
  * The IAM permission boundary policy doesn't determine the specific permissions a user will receive; rather, it sets the limits or boundaries for the policies that will be created

* IAM Policy Evaluation
  * Logic: 
    * By default, all requests are implicity denied except for the AWS account root user.
    * An explicit allow in an identity-based or resource-based policy overrides the default deny (1)
    * If a permissions boundary, Organizations SCP, or session policy is present, an explicit allow is used to limit actions. Anything not explicitly allowed is an implicit deny and may override the decision in (2)
    * An explicit deny in any policy overrides any allows
  * Croos-Account Access Policy Evaluation Logic
    * Both Accounts may allow the request (example: in an identity-based policy in account A and in an resource-based policy in account b)

* IAM Roles vs Resource Based Policies
  * You have two options for permissions in a cross account:
    1. attaching a recource-based policy to a resource (example: S3 bucket policy)
      * The principal does not have to give up his permissions
      * Supported by many services like: Amazon S3 buckets, SNS topics, SQS queues, etc
      * Permanent authotization (as long as it exists in the resource-based policy)
      * You can usse aws:PrincipalOrgID to allow access to the resource only to the organization
    2. using a role as a proxy
      * When you assume a role (user, application or service), you give up your original permissions and take the permissions assigned to the role
      * permissions expire over time.

### ABAC - Attribute-Based Access Control

* Instead of creating IAM roles for every team, use ABAC to group attributes to identify which resources a set of users can access
* Allow operations when the principal's tags matches the resource tag
* Require fewer policies (you do not create different policies for different job functions)
* Permissions automatically granted based on attributes

### IAM MFA:

* if a password is stolen or hacked, the account is not compromised.
* options:
  * Virtual MFA device
  * Universal 2nd Factor (U2F) Security Key
  * Hardware Key Fob MFA Device
  * Hardware Key Fob MFA Device for AWS GovCloud (US)
* You can force MFA in the following ways:
  * Amazon S3 MFA delete (Versioning must be enabled)
  * IAM Conditions - MultiFactorAuthPresent (Compatible with the AWS Console and the AWS CLI)
    ```json
    {
      "Effect": "Deny",
      "Action": ["ec2:TerminateInstance"],
      "Resource": "*",
      "Condition": {
        "BoolIfExists":{
          "aws:MultiFactorAuthPresent": false
        }
      }
      ...
    }
    Deny if multi factor is not present, in another statement you can allow other actions (no critical actions) if the MFA is not present
    ```
  * IAM Conditions - MultiFactorAuthAge (Grant acces only within a specified time after MFA authentication)
* If you have an issue deleting virtual mfa device this is because the user began assigning a virtual MFA and then cancelled the process, to fix this issue, the administraror must use the AWS CLI or AWS API to remove the existing but deactivated device

### IAM Credentials Report

* IAM Users and the status of their passwords, access keys, and MFA devices.
* For automatic remediation use AWS Config with a rule that trigger an SSM Automation to rotate the access keys and then send a notifications through SNS , jira, slack, api endpoints, etc.

### PassRole to Services

* You can grant users permissions to pass an IAM role to an AWS service
* Grant iam:PassRole permission to the user's IAM user, role or group
  ```json
  {
    "Effect": "Allow",
    "Action": ["iam:GetRole", "iam:PassRole"],
    "Resource": "arn:aws:iam:123456789:role:/EC2-roles-for-*",
    ...
  }
  ```

### AWS STS - Security Token Service

* Allow to grant limited and temporary access to AWS
* Token is valid between 15 to 60 min
* You can use STS with:
  * AssumeRole
  * AssumeRoleWithSAML
  * AssumeRoleWithWebIdentity
  * GetSessionToken
* Steps to assume a role:
  * Define an IAM role
  * Define which principals can access this IAM role
  * Use AWS STS to retrieve credentials and impersonate the IAM role (AsummeRole API)
* Versions:
  * STS V1:
    * Global single endpoints "https://sts.amazonaws.com"
    * Only support regions enable by default (you can enable "all regions")
    * Does not work for new regions
  * STS V2:
    * Regional STS endpoints for all regions, reduce latency
    * STS Tokens from regional endpoints (STS V2) are available in all AWS regions
  * Error: An error ocurred (AuthFailure) when calling the DescribeInstances operation: AWS was not able to validate the providede access credentials
    * Solution:
      * Use regional endpoint (V2)
      * Configure STS global enpoint to issue STS tokens V2

### STS External ID

* Piece of data that can be passed to AssumeRole API, allowing the IAM role to be assumed only if this value is present
* Prevent any other customer from tricking 3rd party into unwittingly accessing your resources
  ```json
  {
    "Effect": "Allow",
    "Principal": {"AWS": "3rd party aaccount ID"},
    "Action": ["AssumeRole"],
    "Condition": {
      "StringEquals": {"sts:ExternalId":"12345"}
    }
    "Resource": "arn:aws:iam:123456789:role:/EC2-roles-for-*",
    ...
  }
  ```

### Revoking IAM Role Temporary Credentials

* Users usually have a long session duration time (e.g 12 hours), if credentials are exposed, they can be used for the duration of the session
* Immediately revoke all permissions to the IAM role's credentials issued before a certain time.
* You can find the option called "Revoke Sessions" in the console, this option will add the following policy to your role:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": ["*"],
            "Resource": ["*"],
            "Condition": {
                "DateLessThan": {
                    "aws:TokenIssueTime": "[policy creation time]"
                }
            }
        }
    ]
  }
  ```

### AWS EC2 Instance Metadata Service (IMDS)

* Information about EC2 instance (e.g hostname, instance type, network settings, get temporary credentials, placement, security-groups, tags)
* Metadata is stored in key-value pairs 
* IMDS Service endpoint: http://169.254.169.254/latest/meta-data
* Instance role works calling the IMDS endpoint (http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name) for temporary credentials 
* You can restric IMDS using local firewall or turning off access using AWS console or AWS CLI (HttpEndpoint=false)
* IMDSv1 vs IMDSv2:
  * You can force Metadata version 2 at instance Launch, or use cloudwatch to check when the IMDSv1 is used (MetadataNoToken metric)
  * You can create policy based on the IMDS version using the following condition:
    ```json
    {
      "Condition": {
        "NumericLessThan": {"ec2:RoleDelivery":"2.0"}
      }
    }
    ```
  * Also you can create a policy to prevent launch of EC2 instance using IMDSv1
    ```json
    {
      "Condition": {
        "StringNotEquals": {"ec2:MetadataHttpTokens":"required"}
      }
    }
    ```
  * IMDSv1: 
    * Accessing http://169.254.169.254/latest/meta-data directly 
  * IMDSv2:
    * More secure and is done in two steps
      1. Get session token (limited validity) - using headers & PUT: `$TOKEN='curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"'`
      2. Use Session token IMDSv2 Calls - using headers: `curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"`

### S3 - Authorization Evaluation Process

* User Context: Is the IAM principal authorized by the parent AWS account (IAM Policy)
* Bucket Context: Evaluate the policies of the AWS account that owns the bucket (check for explicit Deny)
* Object Context: Requester must have permission from the object owner (sing Object ACL)
  * If you want to own all objects in your bucket and only use Bucket Policy and IAM-Based Policies to grant access, enable **Bucket Owner Enforced for Object Ownership**
* There are bucket operations (s3:ListBucket) and object operations (s3:GetObject)

### S3 - Cross Account Access

* Ways to grant cross-account access to S3 objects:
  * IAM Policies and S3 Bucket Policy
  * IAM Policies and Access Control lists (ACLs)
    * Only works if **bucket owner enforced setting = disabled**
    * By default, all newly created buckets have **bucket owner enforced setting = Enabled**, ACL are NOT recommended (& disabled by default since Apr 2023)
    * When you use ACLs, there is an object owner, in ths case the user have to give permissions to the bucket owner
      * to grant permissions you need to use an ACL-soecific headers with full permissions (s3:x-amz-grant-full-control) or using a canned ACL (s3:x-amz-acl):
        * s3:x-amz-acl: private
        * s3:x-amz-acl: public-read
        * s3:x-amz-acl: public-read-write
  * Cross-Account IAM Roles
    * To centralize permission management when providing cross-account access to multiple services
    * Bucket policy is not required as the API calls to S3 come from eithin the account (through the assumed IAM role)

### VPC Endpoint Strategy S3

* VPC Gateway Endpoint for Amazon S3:
  * Only Accessed by resources in the VPC where it's created
  * Make sure DNS support is enabled
  * No Cost
* VPC interface endpoint for S3:
  * ENI(s) are deploed in your subnets
  * Can access from on-premises (VPN or Direct Connect)
  * Costs $0.01 per hour per AZ
* You can restric access using `aws:SourceVpc` and `aws:SourceVpce` or `aws:SourceIp` and `aws:VpcSourceIp` (just valid when you start to use VPC endpoints)

### S3 Access Point

* Access Points  simplify management for S3 buckets
* Each Access Point has:
  * its own DNS name (Internet origin or VPC origin)
  * an access point policy (similar to bucket policy) - manage security at scale
* You can define the access point to be accesible only from within the VPC
  * You must create a VPC Endpoint to access the Access Point (Gateway or interface)
  * The VPC endpoint policy must allow access to the target bucket and access point
* When you create an S3 access point it is so important to create an S3 policy to admit request only from the access point

### S3 - Multi-Region Access Point

* Provide a global endpoint that span S3 buckets in multiple AWS regions
* Dinamically route request to the nearest S3 bucket (lowest latency)
* Bi-directional S3 bucket replication rules are created to keep data in sync across regions.
* Failover controls - allows you to shift requests across S3 buckets in different AWS regions within minutes (Active-Active or Active-Passive)

### S3 CORS

* Cross-Origin Resource Sharing (CORS).
* Origin = scheme (protocol) + host (domain) + port.
* Web browser mechanism to allow requests to other origins while visiting the main origin.
* You can add a CORS configuration written in JSON on your S3 bucket

### Cognito

#### User Pools

* Create a serverless database of user for your web & mobile apps 
* You can setup: simple login, password reset, email & phone verification, MFA, Federated Identities (Google login)
* Login sends back a JWT
* Example: login with user pools and then pass the token to AWS API gateway to execute a lambda function
* User Pool Groups: Defines the permissions for users in the group by assiging IAM role to the group, users can be in multiple groups and those ones can have a precedence value

#### Identity Pools

* Get identities for users so they obtain temporary AWS credentials
* You can use as a identity source:
  * Amazon cognito user pools
  * Identity Provider (Google login)
  * OpenID & SAML
  * Custom Login Server (Developer Authenticated Identities)

### Identity Federation in AWS

* Give users outside of AWS permissions to access AWS resources in your account
* You don't need to create IAM Users (User management is outside AWS)
* Use cases:
  * A corporate has its own identity system (e.g active directory)
  * A Web/Mobile app that needs access to AWS resources
* Identity Federation options
  * SAML 2.0:
    * Need to setup a trust between AWS IAM and SAML 2.0 identity provider (both ways)
    * Under-the-hood: Uses the STS API AssumeRoleWithSAML
    * It is important to keep updated the XML file on IAM (aws iam update-saml-provider) that is generated from the IdP
  * Custom Identity Broker Application:
    * Use only if the identity provider is not compatible with SAML 2.0
    * Authenticates and requests temporary credentials from AWS, must determine the appropiate IAM Role
    * Uses the STS API AssumeRole or GetFederationToken
  * Web Identity Federation (with/out cognito) 
    * It is recommended use cognite since this supports: anonymous users, MFA, Data Synchronization
    * After login you can identify the user with an IAM policy variable

### AWS IAM Identity Center (successor to AWS Single Sign-on)

* One login SSO for all your
  * AWS accounts in AWS organizations.
  * Business cloud applications (e.g., Salesforce, Box, Microsoft 365,...).
  * SAML 2.0 - enabled applications.
  * EC2 windows instances.
* Identity Providers
  * Built-in identity store in IAM Identity Center.
  * 3rd party: Active Directory (AD), OneLogin, Okta.
* You can have permissions sets and assign them to groups

### AWS Directory Services

#### Microsoft Active Directory

* Found on any windows server with AD domain services, it is a database of objects (user accounts, computers, printers, file shares, security groups)
* Objects are organized in trees and a group of trees is a forest

#### AWS Directory Services

* AWS Managed Microsoft AD
  * Create your own AD in AWS on a VPC, manage users locally, supports MFA
  * Establish "trust" connections with your on-premises AD.
  * EC2 Windows instances  can join to the domain and run traditional applications (sharepoint etc )
  * It has different integrations like RDS for SQL server, AWS SSo
  * Multi AZ deployment of DC (Domain controller)
  * Automated backups and automated multi-region replication of your directory
  * To stablish a connection you must to have a direct connect (DX) or VPN connection
  * Can setup three kinds of forest trust:
    * One way trust: AWS => On-premise
    * One way trust: On-premise => AWS
    * Two way forest trust: On-premise <=> AWS
  * Forest trust is different than synchronization (replication is not supported), the only way to have replication is creating an instance and deploy AD (actuve directory) on this, then setup replication between on-premise AD and this instance and then configure AWS managed Microsoft AD with two way forest trust
* AD connector 
  * Directory Gateway (proxy) to redirect to on-premises AD, supports MFA
  * Users are managed on the on-premises AD.
  * No caching capabilites 
  * you need VPN or DX
  * Does not work with SQL Server
* Simple AD
  * AD-compatible managed directory on AWS
  * Cannot be joined with on-premise AD
  * Supports joining EC2 instances, manage users and groups
  * Powered by Samba 4, compatible with Microsoft AD
  * Lower cost, low scale, basic AD compatible or LDAP compatibility

## VPC (From AWS Solutions Architect Professional)

### VPC Basics

* IP's
  * CIDR: Block of IP address, example: 192.168.0.0/26 - 192.168.0.63 (64 ip)
  * Private IP: 
    * 10.0.0.0 - 10.255.255.255 (10.0.0.0/8) - Big Networks
    * 172.16.0.0 - 172.31.255.255 (172.16.0.0/12)
    * 192.168.0.0 - 192.168.255.255 (192.168.0.0/16) Home Networks
  * Public IP: All the rest
* VPC:
  * Must have a defined list of CIDR blocks (min size is /28 max size is /16 (65536 IP address))
  * VPC is private so only private IP CIDR ranges are allowed
* Subnets
  * Within a VPC, defined as a CIDR that is a subset of the VPC CIDR
  * All the instances within subnets get a private IP
  * Fist 4 IP and last one in every sunet is reseverd by AWS.
* Route Tables
  * Used to control where the network traffic is directed to
  * Can be associated within specific subnets
  * The "most specific" routin rule is always followed (192.168.0.1/24 beats 0.0.0.0/0)
* Internet Gateay (IGW)
  * Helps our VPC connect to the internet, HA, scales horizontally
  * Acts as a NAT for instances that have a public IPv4 or public IPv6
* Public Subnets
  * Has a route table that sends 0.0.0.0/0 to an IGW
  * Instances must have a public IPv4 to talk to the internet
* Private Subnets
  * Access internet with a NAT instance or NAT Gateway setup in a public subnet (Must edit routes so that 0.0.0.0/0 routes traffic to the NAT)
* NAT instance: 
  * It is an EC2 instance in a public subnet, not resilient to failure, cheap, must disable source/destination check (EC2 setting)
  * You need edit the route in your private subnet to route 0.0.0.0/0 to you NAT instance
* NAT Gateway
  * Managed NAT solution, scales automatically, resilient, has an elastic ip, external services see the IP of the NAT Gateway as the sorce
* Network ACL (NACL)
  * Stateless (reurn traffic must be explicitly allowed by rules) firewall, support allow and deny rules
* Security Groups
  * Applied at the instance level, only support for allow rules (no deny), it is stateful (return traffic is automatically allowed, regardless of rules)
  * Can reference other security groups in the same region (peered VPC, cross-account)

### VPC Peering

* Connect two VPC (you must update route table in each VPC's subnets), privately using AWS network, must not overlapping any CIDR, and it is not trasitive
* You can do VPC peering with another AWS account
* VPC peering can work inter-region, cross account
* You can refer a security group of a peered VPC (work cross account)
* Longest Prefix Match ("most specific route"), it is used in the route tables to know where redirect a traffic in cases where an VPC are peered with other two vpc with the same CIDR
* No edge to edge routing, vpc peering does not support edge to edge routing for NAT devices

### Transit Gateway

* For having transitive peering between thousands of VPC and on-premise, hub-and-spoke (star) connection.
* It is transitive and edge to edge routing, you can limit which VPC can talk with other VPC
* Regional resource, can work cross-region 
* Share cross-account using Resource Access Manager (RAM)
* Works with direct connect gateway, VPN connections, instances in a VPC can access a NAT Gateway, NLB, privateLink and EFS in other VPCs
* Supports **Ip multicast** (Not supported by any other AWS service)

### VPC Endpoints

* Allow you to connect to AWS services using a private network, it scales horizontally and redundant
* VPC Endpoint Gateway (only works for S3 & DynamoDB)
  * Must update route tables entries
  * Gateway is defined at the vpc level
  * DNS resolution must be enabled in the VPC
  * The same public hostname for S3 can be used
  * Gateway endpoint cannot be extended out of a VPC (VPN, DX, TGW, peering)
* VPC Endpoint Interface (All except DynamoDB)
  * Provision an ENI that will have a private endpoint interface hostname
  * Leverage Security Groups for security
  * Interface can be accessed from direct connect and site to site VPN
  * You can access with the public DNS if the **private DNS setting is enabled** also the vpc settings 2DNS hostnames and DNS support must be true
* VPC Endpoints Policies:
  * JSON documents to control acces to services
  * Another level of protection (VPC Endpoint Level), does not override or replace IAM user policies or service-specific policies (such as S3 bucket policies)
  * The IAM user can still use the resource outside the VPC endpoint unless you add a policy to deny any action not done through the vpc endpoint (`Condition:"aws:sourceVpce":"vpce-11111"` or `Condition:"aws:sourceVpc":"vpc-11111"`)
  * To restrict access based on private traffic use sourceVpce or sourceVpc conditions, in the case you want to restric public ip you have to use sourceIP condition

### AWS PrivateLink (VPC Endpoint Services)

* Most secure & scalable way to expose a service to 1000s of VPC (own or other accounts).
* Does not require VPC peering, internet gateway, NAT, route tables
* Requires a network load balancer (service VPC) and ENI (Customer VPC) or GWLB.
* the solutions can be fault tolerant (multiple AZ).

### Site to Site VPN (AWS managed VPN)

* To establish a secure and private connection between your on-premises network or data center and your virtual private cloud (VPC) on AWS
* setup:
  * on-premise:
    * setup hardware or software VPN that must to be accessible through internet
  * AWS
    * Setup a virtual private gateway (VGW) and attach to the vpc
    * Setup a customer gateway (CGW) to point the on-premise vpn
* Two vpn connections (tunnels) are created for redundancy, encrypted using IPsec
* You can use aws global acceletaror to make it globally
* You can propagate to reach the on-premises or aws instances, for this you must do:
  * Static Routing: Update routing tables
  * Dynamic Routing: Use BGP (Border Gateway Protocol) to sahre routes automatically just need to specify the ASN (Autonomus System Number) of CGW and VGW
* To have internet on you S2S you can use NAT instance (on the aws or on premises side), AWS NAT Gateway won't allow the internet traffic due restrictions
* AWS VPN Cloud Hub can conect up to 10 CGW for each PGW
* AWS Recommend creating a separate VPN connection for each customer VPC, (create VGW as many VPC you have)
  * To address this issue, you have two viable options: Direct Connect or leveraging shared services architecture. With shared services architecture, all VPCs are interconnected either through VPC peering or transit gateway. However, only one VPC requires a site-to-site VPN connection. This particular VPC functions as a hub for shared services, housing replicated or proxy services. Consequently, all other VPCs can communicate seamlessly through this central hub.

### AWS Client VPN

* Allows to connect from your computer using OpenVPNto your private network in AWS and on-premises
* Enable to get a private connection with AWS and therefore any network architecture on AWS should work with client VPN

### Direct Connect

* Provides a dedicated private connection (More expensive than run a VPN solution) from a remote network to you VPC (Through VIF).
* Dedicated connection must be setup between you data center and AWS direct connections locations

### On-premises Redundant Connections

* Solutions to have redundant connections:
  * Active-Active VPN connections (have to on-premises datacenter connected, with a CW for each of them conected to one VGW)
  * Multiple connections at multiple AWS Direct locations (have to on-premises datacenter connected, with direct connect)
  * Backup VPN location (have both direct connect and S2S connection)
  * Direct Connect Gateway - SiteLink (on-premise datacenters don't need to have connection)


## Management and Security Governance

### AWS Organizations

* Allows to manage multiple AWS accounts
* The main account is the management account and other accounts are member accounts
* Member accounts can only be part of one organization
* Consolidated billing across all accounts - single payment method (princing benefits from aggreagated usage)
* Shared  reserved instances and saving plans discounts across accounts
* Advantages:
  * Multi account vs one account multi VPC
  * Use tagging standards for billing purposes
  * Enable CloudTrail on all accounts, send logs to central S3 account
  * Send cloudwatch logs to central logging account.
  * Establish cross Account Roles fo Admin purposes.
  * You can use aws:principalOrgID condition to restrict access to IAM principals from accounts in an AWS organizations
  * Service Control Policies (SCP)
    * IAM Policies applied to OU or accounts to restrict Users and Roles
    * They do not apply to the management account (full admin power always)
    * Must have an explicit allow (does not allow anything by default)

### AWS Control Tower

* Easy way to set up and govern a secure and compliant multi-account AWS environment based on best practices
* Benefits:
  * Automate the set up of your environment in a few clicks
  * Automate ongoing policy management using guardrails 
    * it has mandatory, strongly recommended and elective levels
  * Detect Policy violations and remediate them
  * Monitor compliance through an interactive dashboard
* AWS Control Tower runs on top of AWS Organizations
  * It automatically sets up AWS Organizations to organize accounts and implement SCPs

---