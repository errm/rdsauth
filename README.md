# RDS IAM Token Authentication

[![Go Reference](https://pkg.go.dev/badge/github.com/errm/rdsauth.svg)](https://pkg.go.dev/github.com/errm/rdsauth)
[![CI](https://github.com/errm/rdsauth/actions/workflows/ci.yaml/badge.svg)](https://github.com/errm/rdsauth/actions/workflows/ci.yaml)

* RDS IAM authentication tokens are valid for 15 minutes.
* IAM database authentication throttles connections at 200 new connections per second.
* Connections that use the same authentication token are not throttled. It is recommended that you reuse authentication tokens when possible.

## Usage

```go
import (
	"database/sql"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/go-sql-driver/mysql"
	rdsauth "github.com/errm/rdsauth/mysql"
)

func main() {
	// Load AWS configuration
	cfg, _ := config.LoadDefaultConfig(context.TODO())

	// Configure MySQL connection
	mysqlConfig := mysql.NewConfig()
	mysqlConfig.User = "dbuser"
        mysqlConfig.Addr = "db-instance.region.rds.amazonaws.com:3306"
        mysqlConfig.Net = "tcp"

        // Register the token provider
        mysqlCfg.Apply(mysql.BeforeConnect(rdsauth.TokenProvider(cfg, 60*time.Second)))

        connector, _ := mysql.NewConnector(mysqlConfig)

	// Open database connection
	db, _ := sql.OpenDB(connector)
	defer db.Close()
	err := db.Ping()
	if err != nil {
		log.Fatal(err)
	}
}
```
