package mysql

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/go-sql-driver/mysql"
)

func TestTokenProvider(t *testing.T) {
	mysqlConfig := mysql.Config{
		Addr: "prod-instance.us-east-1.rds.amazonaws.com:3306",
		User: "admin",
	}
	creds := &staticCredentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "anExampleSessionToken"}
	tp := TokenProvider(aws.Config{Credentials: creds}, time.Minute)
	err := tp(t.Context(), &mysqlConfig)
	if err != nil {
		t.Fatal(err)
	}
	if mysqlConfig.Passwd == "" {
		t.Fatal("expected non-empty password")
	}
}

func TestExpiredToken(t *testing.T) {
	mysqlConfig := mysql.Config{
		Addr: "prod-instance.us-east-1.rds.amazonaws.com:3306",
		User: "admin",
	}
	creds := &staticCredentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "anExampleSessionToken"}
	ct := &cachedToken{
		awsConfig:   aws.Config{Credentials: creds},
		mutex:       &sync.RWMutex{},
		token:       "stale token",
		expires:     time.Now().Add(30 * time.Second),
		gracePeriod: time.Minute,
	}
	err := ct.get(t.Context(), &mysqlConfig)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if mysqlConfig.Passwd == "stale token" {
		t.Fatal("expected token refresh")
	}
	if !ct.expires.Before(time.Now().Add(16 * time.Minute)) {
		t.Fatal("expected expiry time to be refreshed")
	}
	if !ct.expires.After(time.Now().Add(14 * time.Minute)) {
		t.Fatal("expected expiry time to be refreshed")
	}
}

func TestCachedToken(t *testing.T) {
	mysqlConfig := mysql.Config{}
	ct := &cachedToken{
		mutex:   &sync.RWMutex{},
		token:   "cached token",
		expires: time.Now().Add(10 * time.Second),
	}
	err := ct.get(t.Context(), &mysqlConfig)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if mysqlConfig.Passwd != "cached token" {
		t.Fatal("expected cached token")
	}
}

func TestError(t *testing.T) {
	mysqlConfig := mysql.Config{
		Addr: "prod-instance.us-east-1.rds.amazonaws.com",
		User: "admin",
	}
	creds := &staticCredentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "anExampleSessionToken"}
	tp := TokenProvider(aws.Config{Credentials: creds}, 60*time.Second)
	err := tp(t.Context(), &mysqlConfig)
	if !strings.Contains(err.Error(), "missing a port") {
		t.Fatalf("expected missing port error, got %v", err)
	}
}

func TestExpiryParsing(t *testing.T) {
	cases := []struct {
		name          string
		input         string
		expected      time.Time
		expectedError string
	}{
		{
			name:     "token with valid time and expiry",
			input:    "prod-instance.us-east-1.rds.amazonaws.com:3306?X-Amz-Date=20250704T100138Z&X-Amz-Expires=900",
			expected: time.Date(2025, time.July, 04, 10, 16, 38, 0, time.UTC),
		},
		{
			name:          "token missing expiry",
			input:         "prod-instance.us-east-1.rds.amazonaws.com:3306?X-Amz-Date=20250704T100138Z",
			expectedError: "X-Amz-Expires not found in auth token",
		},
		{
			name:          "token missing time",
			input:         "prod-instance.us-east-1.rds.amazonaws.com:3306?X-Amz-Expires=900",
			expectedError: "X-Amz-Date not found in auth token",
		},
		{
			name:          "token with invalid time",
			input:         "prod-instance.us-east-1.rds.amazonaws.com:3306?X-Amz-Date=Tuesday&X-Amz-Expires=900",
			expectedError: "cannot parse \"Tuesday\"",
		},
		{
			name:          "token with invalid expiry",
			input:         "prod-instance.us-east-1.rds.amazonaws.com:3306?X-Amz-Date=20250704T100138Z&X-Amz-Expires=NineHundred",
			expectedError: "\"NineHundred\": invalid syntax",
		},
		{
			name:          "token is an invalid url",
			input:         "http://1 2 3.com",
			expectedError: "host name",
		},
		{
			name:          "token has invalid query string",
			input:         "123.com?a=1;b=2",
			expectedError: "invalid semicolon separator in query",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := expiry(tc.input)
			if len(tc.expectedError) > 0 {
				if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error %v, got %v", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if actual != tc.expected {
					t.Errorf("expected %v, got %v", tc.expected, actual)
				}
			}
		})
	}
}

func TestConcurrentTokenProvider(t *testing.T) {
	mysqlConfig := mysql.Config{
		Addr: "prod-instance.us-east-1.rds.amazonaws.com:3306",
		User: "admin",
	}
	creds := &staticCredentials{"AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "anExampleSessionToken"}
	// grace period is larger than token expiry, so all tokens need to be refreshed right away -  I think this is the worst case scenario
	tp := TokenProvider(aws.Config{Credentials: creds}, 16*time.Minute)

	const goroutineCount = 1000
	var wg sync.WaitGroup
	errs := make(chan error, goroutineCount)

	// Run many goroutines to call the token provider concurrently
	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conf := mysqlConfig // copy
			err := tp(context.Background(), &conf)
			errs <- err
			if conf.Passwd == "" {
				t.Errorf("expected non-empty password")
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

type staticCredentials struct {
	AccessKey, SecretKey, Session string
}

func (s *staticCredentials) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return aws.Credentials{
		AccessKeyID:     s.AccessKey,
		SecretAccessKey: s.SecretKey,
		SessionToken:    s.Session,
	}, nil
}
