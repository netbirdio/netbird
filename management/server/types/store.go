package types

import "github.com/netbirdio/netbird/management/internals/shared/db"

type Engine = db.Engine

const (
	PostgresStoreEngine        = db.PostgresStoreEngine
	FileStoreEngine     Engine = "jsonfile"
	SqliteStoreEngine          = db.SqliteStoreEngine
	MysqlStoreEngine           = db.MysqlStoreEngine
)
