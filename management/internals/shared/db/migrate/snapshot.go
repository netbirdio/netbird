package migrate

import (
	"fmt"
	"slices"
	"sort"

	"gorm.io/gorm"
)

// ColumnSchema describes one column as the database reports it.
type ColumnSchema struct {
	Name       string
	Type       string
	Nullable   bool
	PrimaryKey bool
	Unique     bool
	Default    string
}

// IndexSchema describes one index as the database reports it.
type IndexSchema struct {
	Name       string
	Columns    []string
	Unique     bool
	PrimaryKey bool
}

// TableSchema is the introspected shape of one table.
type TableSchema struct {
	Columns []ColumnSchema
	Indexes []IndexSchema
}

// SchemaSnapshot introspects every table of the database except the ignored
// ones, in a form that compares equal for two databases with the same schema.
// Drift tests use it to hold the migrations of a set to the schema gorm
// derives from the models.
func SchemaSnapshot(gormDB *gorm.DB, ignoreTables ...string) (map[string]TableSchema, error) {
	migrator := gormDB.Migrator()
	tables, err := migrator.GetTables()
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	snapshot := make(map[string]TableSchema, len(tables))
	for _, table := range tables {
		if table == "sqlite_sequence" || slices.Contains(ignoreTables, table) {
			continue
		}
		columnTypes, err := migrator.ColumnTypes(table)
		if err != nil {
			return nil, fmt.Errorf("columns of %s: %w", table, err)
		}
		indexes, err := migrator.GetIndexes(table)
		if err != nil {
			return nil, fmt.Errorf("indexes of %s: %w", table, err)
		}

		var ts TableSchema
		for _, column := range columnTypes {
			nullable, _ := column.Nullable()
			primaryKey, _ := column.PrimaryKey()
			unique, _ := column.Unique()
			defaultValue, _ := column.DefaultValue()
			ts.Columns = append(ts.Columns, ColumnSchema{
				Name:       column.Name(),
				Type:       column.DatabaseTypeName(),
				Nullable:   nullable,
				PrimaryKey: primaryKey,
				Unique:     unique,
				Default:    defaultValue,
			})
		}
		for _, index := range indexes {
			unique, _ := index.Unique()
			primaryKey, _ := index.PrimaryKey()
			ts.Indexes = append(ts.Indexes, IndexSchema{
				Name:       index.Name(),
				Columns:    index.Columns(),
				Unique:     unique,
				PrimaryKey: primaryKey,
			})
		}
		sort.Slice(ts.Columns, func(i, j int) bool { return ts.Columns[i].Name < ts.Columns[j].Name })
		sort.Slice(ts.Indexes, func(i, j int) bool { return ts.Indexes[i].Name < ts.Indexes[j].Name })
		snapshot[table] = ts
	}
	return snapshot, nil
}
