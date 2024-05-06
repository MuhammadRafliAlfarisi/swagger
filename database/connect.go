package database

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
)

var DB *sql.DB

func init() {

	dbConnectionString := fmt.Sprintf("root@tcp(localhost:3306)/go")

	var err error
	DB, err = sql.Open("mysql", dbConnectionString)
	if err != nil {
		log.Fatal(err)
	}
}
