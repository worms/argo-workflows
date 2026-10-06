Description: Support AWS RDS IAM database authentication for MySQL and MariaDB
Authors: [Ian Wormsbecker](https://github.com/worms)
Component: General
Issues: 17135

The `mysql` database configuration now supports `awsRDSToken`, matching the existing PostgreSQL support.
When enabled, the controller authenticates to AWS RDS for MySQL, MariaDB or Aurora MySQL with a short-lived IAM token instead of the `passwordSecret`.
A fresh token is built from the default AWS credential chain, such as IRSA, for each new database connection.
TLS must be enabled with the `tls` connection option, since the token is sent using the cleartext authentication plugin.
See [IAM-based Authentication](https://argo-workflows.readthedocs.io/en/latest/workflow-archive/#iam-based-authentication) for configuration details.
