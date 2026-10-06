package sqldb

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/lib/pq"
)

type awsRDSConnector struct {
	dsn      string
	endpoint string
	username string
	region   string
}

// buildRDSAuthToken loads the default AWS credential chain and returns a short-lived RDS IAM
// authentication token for username at endpoint (host:port). If region is empty it is resolved
// from the AWS configuration.
func buildRDSAuthToken(ctx context.Context, endpoint, region, username string) (string, error) {
	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	token, err := auth.BuildAuthToken(ctx, endpoint, awsCfg.Region, username, awsCfg.Credentials)
	if err != nil {
		return "", fmt.Errorf("failed to build RDS auth token: %w", err)
	}
	return token, nil
}

func (c *awsRDSConnector) Connect(ctx context.Context) (driver.Conn, error) {
	token, err := buildRDSAuthToken(ctx, c.endpoint, c.region, c.username)
	if err != nil {
		return nil, err
	}

	// Escape single quotes in token for safe DSN interpolation
	escapedToken := strings.ReplaceAll(token, "'", "\\'")

	dsnWithPassword := fmt.Sprintf("%s password='%s'", c.dsn, escapedToken)

	return pq.Driver{}.Open(dsnWithPassword)
}

func (c *awsRDSConnector) Driver() driver.Driver {
	return pq.Driver{}
}
