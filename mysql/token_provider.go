// Package mysql provides a token provider for AWS RDS IAM database authentication.
//
//   - RDS IAM authentication tokens are valid for 15 minutes.
//   - IAM database authentication throttles connections at 200 new connections per second.
//   - Connections that use the same authentication token are not throttled. It is recommended that you reuse authentication tokens when possible.
//
// The token provider is safe for concurrent use.
//
// Example usage:
//
//	import (
//		"database/sql"
//		"github.com/aws/aws-sdk-go-v2/config"
//		"github.com/go-sql-driver/mysql"
//		rdsauth "github.com/errm/rdsauth/mysql"
//	)
//
//	func main() {
//		// Load AWS configuration
//		cfg, _ := config.LoadDefaultConfig(context.TODO())
//
//		// Configure MySQL connection
//		mysqlConfig := mysql.NewConfig()
//		mysqlConfig.User = "dbuser"
//	        mysqlConfig.Addr = "db-instance.region.rds.amazonaws.com:3306"
//	        mysqlConfig.Net = "tcp"
//
//	        // Register the token provider
//	        mysqlCfg.Apply(mysql.BeforeConnect(rdsauth.TokenProvider(cfg, time.Minute)))
//
//	        connector, _ := mysql.NewConnector(mysqlConfig)
//
//		// Open database connection
//		db, _ := sql.OpenDB(connector)
//		defer db.Close()
//		err := db.Ping()
//		if err != nil {
//			log.Fatal(err)
//		}
//	}
package mysql

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/go-sql-driver/mysql"
)

// cachedToken holds the authentication token and its expiration time.
// It includes a mutex to ensure safe concurrent access to the token state.
type cachedToken struct {
	token       string
	expires     time.Time
	gracePeriod time.Duration
	mutex       *sync.RWMutex
	awsConfig   aws.Config
}

// TokenProvider creates a new AWS RDS authentication token provider function.
// The returned function can be used as an AuthSwitchRequest handler in the MySQL driver.
//
// The token provider caches tokens until they are close to expiration (within the grace period),
// reducing the number of calls to the AWS authentication service.
//
// Parameters:
//   - awsConfig: AWS configuration containing credentials and region information
//   - gracePeriod: The duration before token expiration when a new token should be fetched
//
// Returns:
//   - A function that can be used as an BeforeConnect Option for the MySQL driver
func TokenProvider(awsConfig aws.Config, gracePeriod time.Duration) func(ctx context.Context, c *mysql.Config) error {
	ct := &cachedToken{
		awsConfig:   awsConfig,
		mutex:       &sync.RWMutex{},
		gracePeriod: gracePeriod,
	}
	return ct.get
}

// get retrieves a valid authentication token, either from cache or by generating a new one.
// It handles token caching and refreshing based on expiration
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - c: MySQL configuration where the token will be set
//
// Returns:
//   - error: If token generation fails
func (ct *cachedToken) get(ctx context.Context, c *mysql.Config) error {
	// First check with a read lock to see if we have a valid token
	ct.mutex.RLock()
	if !ct.stale() {
		defer ct.mutex.RUnlock()
		c.Passwd = ct.token
		return nil
	}
	ct.mutex.RUnlock()

	// If we get here, we need to update the token
	// Only one goroutine should be able to update the token at a time
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	// Check again in case another goroutine already updated the token
	if !ct.stale() {
		c.Passwd = ct.token
		return nil
	}

	// Update the token
	return ct.updateToken(ctx, c)
}

// stale checks if the current token is expired or about to expire.
// A token is considered stale if it's either empty or its expiration time
// is within the grace period.
//
// Returns:
//   - bool: true if the token is stale and should be refreshed
func (ct *cachedToken) stale() bool {
	return ct.token == "" || time.Now().After(ct.expires.Add(-ct.gracePeriod))
}

// updateToken generates a new authentication token and updates the cache.
// It should only be called when holding the write lock.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//   - c: MySQL configuration containing connection details
//
// Returns:
//   - error: If token generation fails or context is cancelled
//
// This function is not safe for concurrent access and should be called
// while holding the cache's write lock.
func (ct *cachedToken) updateToken(ctx context.Context, c *mysql.Config) error {
	var err error
	if ct.token, err = auth.BuildAuthToken(
		ctx,
		c.Addr,
		os.Getenv("AWS_REGION"),
		c.User,
		ct.awsConfig.Credentials,
	); err != nil {
		return err
	}
	c.Passwd = ct.token
	ct.expires, err = expiry(ct.token)
	return err
}

// expiry parses the expiration time from an RDS authentication token.
// The token is expected to be a URL-encoded string containing AWS authentication parameters.
//
// Parameters:
//   - token: The authentication token string from AWS RDS
//
// Returns:
//   - time.Time: The calculated expiration time of the token
//   - error: If the token is malformed or missing required parameters
//
// The function expects the token to contain X-Amz-Date and X-Amz-Expires parameters.
// The actual expiration time is calculated as (X-Amz-Date + X-Amz-Expires).
func expiry(token string) (time.Time, error) {
	var t time.Time
	u, err := url.Parse(token)
	if err != nil {
		return t, err
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return t, err
	}
	date, found := q["X-Amz-Date"]
	if found {
		t, err = time.Parse("20060102T150405Z", date[0])
		if err != nil {
			return t, err
		}
	} else {
		return t, errors.New("X-Amz-Date not found in auth token")
	}
	exp, found := q["X-Amz-Expires"]
	if found {
		expires, err := strconv.Atoi(exp[0])
		if err != nil {
			return t, err
		}
		t = t.Add(time.Duration(expires) * time.Second)
	} else {
		return t, errors.New("X-Amz-Expires not found in auth token")
	}

	return t, nil
}
