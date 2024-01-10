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

### VPC Traffic Mirroring

* Allows you to capture and inspect network traffic in your VPC, routing the traffic to security appliances that you manage
* Capture all the packets or capture the packets of your interest
* Uses cases: content inspection, threat monitoring, troubleshooting
* You can use VPC peering to send data across VPC's

### VPC Network Access Analyzer

* Helps to define conditions to check if the network meet your requirements
* Network Access Scope: Json document that contains conditions to define your network security policy (e.g detect public databases).
* Evaluate against the Json to find issues or demostrate compliance

### Route53 Query Loggin

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

* Connect from your computer usiing OpenVPN to your private network in AWS and on-premises
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
  * if you use custom DNS domain names in a private hosted zone in R53, you myst set bith attributes (enableDnsSupport, & enableDnsHostnames) to true

### VPC Endpoints

* Endpoints allow you to connect to AWS servicces using a private network instead of the public www network, they sacale horizontally and are redundant
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

### PrivateLink (Endpoint Service)

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
>Ephemeral Ports: For any two endpoints to establish a connection, they must use a ports, the endpoint that send the request also send a ephemeral port (random port, different ranges between O.S) to receive the response.
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
* Site to site VPN **ECMP (Equal cost milti-path routing)** 
  * Create multiple site-to-site VPN connections to increase the bandwitch of you connections to AWS.
* You can share transit gateway with direccct connect 

### AWS Cloudfront (CDN - Content Delivery Network)

* 216 Point of presence globally (edge locations), improves user experienc, improving read performance, content is chached at the edge.
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
* Rules are applied to new resourcesas they are created

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

### Route53 - DNSSEC


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