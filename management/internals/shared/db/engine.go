package db

// Engine identifies the SQL engine behind a Conn.
type Engine string

const (
	SqliteStoreEngine   Engine = "sqlite"
	PostgresStoreEngine Engine = "postgres"
	MysqlStoreEngine    Engine = "mysql"
)
