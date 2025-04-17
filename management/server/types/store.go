package types

type Engine string

const (
	PostgresStoreEngine Engine = "postgres"
	FileStoreEngine     Engine = "jsonfile"
	SqliteStoreEngine   Engine = "sqlite"
	MysqlStoreEngine    Engine = "mysql"
)
