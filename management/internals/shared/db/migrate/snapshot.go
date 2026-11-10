package migrate

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"gorm.io/gorm"
)

const (
	postgresDialect = "postgres"
	sqliteDialect   = "sqlite"
)

// ColumnSchema describes one column as the database reports it.
type ColumnSchema struct {
	Name string
	// Type is the full declared type including length and precision.
	Type     string
	Nullable bool
	Default  string
	// Identity is the identity kind, owned sequence or AUTOINCREMENT of the column.
	Identity  string
	Generated string
	Collation string
}

// IndexSchema describes one index. Definition holds everything that shapes
// the index: key columns with their order, direction and collation,
// expressions, uniqueness and the predicate of a partial index.
type IndexSchema struct {
	Name       string
	Definition string
}

// ConstraintSchema describes one primary key, unique, foreign key or check
// constraint. SQLite does not expose constraint names, so they are left empty there.
type ConstraintSchema struct {
	Name       string
	Definition string
}

// TableSchema is the introspected shape of one table.
type TableSchema struct {
	Columns     []ColumnSchema
	Indexes     []IndexSchema
	Constraints []ConstraintSchema
	Options     string
}

// SchemaSnapshot introspects every table of the database except the ignored
// ones, in a form that compares equal for two databases with the same schema.
// Drift tests use it to hold the migrations of a set to the schema gorm
// derives from the models.
func SchemaSnapshot(gormDB *gorm.DB, ignoreTables ...string) (map[string]TableSchema, error) {
	var introspect func(*gorm.DB, string) (TableSchema, error)
	var listTables func(*gorm.DB) ([]string, error)
	switch dialect := gormDB.Dialector.Name(); dialect {
	case postgresDialect:
		listTables, introspect = postgresTables, postgresTable
	case sqliteDialect:
		listTables, introspect = sqliteTables, sqliteTable
	default:
		return nil, fmt.Errorf("unsupported dialect %q", dialect)
	}

	tables, err := listTables(gormDB)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	snapshot := make(map[string]TableSchema, len(tables))
	for _, table := range tables {
		if slices.Contains(ignoreTables, table) {
			continue
		}
		ts, err := introspect(gormDB, table)
		if err != nil {
			return nil, fmt.Errorf("introspect %s: %w", table, err)
		}
		sort.Slice(ts.Columns, func(i, j int) bool { return ts.Columns[i].Name < ts.Columns[j].Name })
		sort.Slice(ts.Indexes, func(i, j int) bool {
			return ts.Indexes[i].Name+ts.Indexes[i].Definition < ts.Indexes[j].Name+ts.Indexes[j].Definition
		})
		sort.Slice(ts.Constraints, func(i, j int) bool {
			return ts.Constraints[i].Name+ts.Constraints[i].Definition < ts.Constraints[j].Name+ts.Constraints[j].Definition
		})
		snapshot[table] = ts
	}
	return snapshot, nil
}

type postgresColumn struct {
	Name      string
	Type      string
	Nullable  bool
	Default   string
	Identity  string
	Generated string
	Sequence  string
	Collation string
}

func postgresTables(gormDB *gorm.DB) ([]string, error) {
	var tables []string
	err := gormDB.Raw(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')`).Scan(&tables).Error
	return tables, err
}

func postgresTable(gormDB *gorm.DB, table string) (TableSchema, error) {
	var columns []postgresColumn
	err := gormDB.Raw(`SELECT a.attname AS name,
			format_type(a.atttypid, a.atttypmod) AS type,
			NOT a.attnotnull AS nullable,
			COALESCE(pg_get_expr(d.adbin, d.adrelid), '') AS "default",
			CASE a.attidentity WHEN 'a' THEN 'always' WHEN 'd' THEN 'by default' ELSE '' END AS identity,
			CASE a.attgenerated WHEN 's' THEN 'stored' WHEN 'v' THEN 'virtual' ELSE '' END AS generated,
			COALESCE(pg_get_serial_sequence(quote_ident(?), a.attname), '') AS sequence,
			COALESCE(co.collname, '') AS collation
		FROM pg_attribute a
		JOIN pg_type t ON t.oid = a.atttypid
		LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		LEFT JOIN pg_collation co ON co.oid = a.attcollation AND a.attcollation <> t.typcollation
		WHERE a.attrelid = quote_ident(?)::regclass AND a.attnum > 0 AND NOT a.attisdropped`, table, table).Scan(&columns).Error
	if err != nil {
		return TableSchema{}, fmt.Errorf("columns: %w", err)
	}

	var ts TableSchema
	for _, column := range columns {
		identity := column.Identity
		if column.Sequence != "" {
			identity += " sequence " + column.Sequence
		}
		ts.Columns = append(ts.Columns, ColumnSchema{
			Name:      column.Name,
			Type:      column.Type,
			Nullable:  column.Nullable,
			Default:   column.Default,
			Identity:  strings.TrimSpace(identity),
			Generated: column.Generated,
			Collation: column.Collation,
		})
	}

	err = gormDB.Raw(`SELECT ic.relname AS name,
			pg_get_indexdef(i.indexrelid) || CASE WHEN i.indisvalid THEN '' ELSE ' INVALID' END AS definition
		FROM pg_index i JOIN pg_class ic ON ic.oid = i.indexrelid
		WHERE i.indrelid = quote_ident(?)::regclass`, table).Scan(&ts.Indexes).Error
	if err != nil {
		return TableSchema{}, fmt.Errorf("indexes: %w", err)
	}

	err = gormDB.Raw(`SELECT conname AS name, pg_get_constraintdef(oid) AS definition
		FROM pg_constraint WHERE conrelid = quote_ident(?)::regclass AND contype <> 'n'`, table).Scan(&ts.Constraints).Error
	if err != nil {
		return TableSchema{}, fmt.Errorf("constraints: %w", err)
	}
	return ts, nil
}

type sqliteColumn struct {
	Name    string
	Type    string
	NotNull bool
	Default *string
	PK      int
	Hidden  int
}

type sqliteIndex struct {
	Name    string
	Unique  bool
	Origin  string
	Partial bool
}

type sqliteIndexColumn struct {
	Seqno int
	Cid   int
	Name  *string
	Desc  bool
	Coll  string
}

type sqliteForeignKey struct {
	ID       int
	Parent   string
	Child    string
	Target   *string
	OnUpdate string
	OnDelete string
}

func sqliteTables(gormDB *gorm.DB) ([]string, error) {
	var tables []string
	err := gormDB.Raw(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'`).Scan(&tables).Error
	return tables, err
}

func sqliteTable(gormDB *gorm.DB, table string) (TableSchema, error) {
	var ddl *string
	if err := gormDB.Raw(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&ddl).Error; err != nil {
		return TableSchema{}, fmt.Errorf("definition: %w", err)
	}
	if ddl == nil {
		return TableSchema{}, fmt.Errorf("no definition")
	}
	items, options := splitDefinition(normalizeSQL(*ddl))

	var columns []sqliteColumn
	err := gormDB.Raw(`SELECT name, type, "notnull" AS not_null, dflt_value AS "default", pk, hidden
		FROM pragma_table_xinfo(?)`, table).Scan(&columns).Error
	if err != nil {
		return TableSchema{}, fmt.Errorf("columns: %w", err)
	}

	ts := TableSchema{Options: options}
	checks, definitions := parseColumnDefinitions(items)
	var primaryKey []sqliteColumn
	for _, column := range columns {
		extras := definitions[normalizeSQL(column.Name)]
		schema := ColumnSchema{
			Name:      column.Name,
			Type:      normalizeSQL(column.Type),
			Nullable:  !column.NotNull,
			Collation: extras.collation,
		}
		if column.Default != nil {
			schema.Default = normalizeSQL(*column.Default)
		}
		if extras.autoincrement {
			schema.Identity = "autoincrement"
		}
		switch column.Hidden {
		case 2:
			schema.Generated = "virtual"
		case 3:
			schema.Generated = "stored"
		}
		ts.Columns = append(ts.Columns, schema)
		if column.PK > 0 {
			primaryKey = append(primaryKey, column)
		}
	}
	if len(primaryKey) > 0 {
		sort.Slice(primaryKey, func(i, j int) bool { return primaryKey[i].PK < primaryKey[j].PK })
		names := make([]string, len(primaryKey))
		for i, column := range primaryKey {
			names[i] = normalizeSQL(column.Name)
		}
		ts.Constraints = append(ts.Constraints, ConstraintSchema{Definition: "primary key(" + strings.Join(names, ",") + ")"})
	}
	for _, check := range checks {
		ts.Constraints = append(ts.Constraints, ConstraintSchema{Definition: "check(" + check + ")"})
	}

	foreignKeys, err := sqliteForeignKeys(gormDB, table)
	if err != nil {
		return TableSchema{}, err
	}
	ts.Constraints = append(ts.Constraints, foreignKeys...)

	ts.Indexes, err = sqliteIndexes(gormDB, table)
	if err != nil {
		return TableSchema{}, err
	}
	return ts, nil
}

func sqliteForeignKeys(gormDB *gorm.DB, table string) ([]ConstraintSchema, error) {
	var rows []sqliteForeignKey
	err := gormDB.Raw(`SELECT id, "table" AS parent, "from" AS child, "to" AS target, on_update, on_delete
		FROM pragma_foreign_key_list(?) ORDER BY id, seq`, table).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("foreign keys: %w", err)
	}

	type foreignKey struct {
		parent, onUpdate, onDelete string
		children, targets          []string
	}
	var order []int
	byID := map[int]*foreignKey{}
	for _, row := range rows {
		fk, ok := byID[row.ID]
		if !ok {
			fk = &foreignKey{parent: normalizeSQL(row.Parent), onUpdate: row.OnUpdate, onDelete: row.OnDelete}
			byID[row.ID] = fk
			order = append(order, row.ID)
		}
		fk.children = append(fk.children, normalizeSQL(row.Child))
		if row.Target != nil {
			fk.targets = append(fk.targets, normalizeSQL(*row.Target))
		}
	}

	var constraints []ConstraintSchema
	for _, id := range order {
		fk := byID[id]
		if len(fk.targets) == 0 {
			var targets []string
			err := gormDB.Raw(`SELECT lower(name) FROM pragma_table_info(?) WHERE pk > 0 ORDER BY pk`, fk.parent).Scan(&targets).Error
			if err != nil {
				return nil, fmt.Errorf("primary key of %s: %w", fk.parent, err)
			}
			fk.targets = targets
		}
		constraints = append(constraints, ConstraintSchema{Definition: fmt.Sprintf("foreign key(%s) references %s(%s) on update %s on delete %s",
			strings.Join(fk.children, ","), fk.parent, strings.Join(fk.targets, ","), strings.ToLower(fk.onUpdate), strings.ToLower(fk.onDelete))})
	}
	return constraints, nil
}

func sqliteIndexes(gormDB *gorm.DB, table string) ([]IndexSchema, error) {
	var indexes []sqliteIndex
	err := gormDB.Raw(`SELECT name, "unique", origin, partial FROM pragma_index_list(?)`, table).Scan(&indexes).Error
	if err != nil {
		return nil, fmt.Errorf("indexes: %w", err)
	}

	var schemas []IndexSchema
	for _, index := range indexes {
		var columns []sqliteIndexColumn
		err := gormDB.Raw(`SELECT seqno, cid, name, "desc", coll FROM pragma_index_xinfo(?) WHERE "key" = 1 ORDER BY seqno`, index.Name).Scan(&columns).Error
		if err != nil {
			return nil, fmt.Errorf("columns of index %s: %w", index.Name, err)
		}
		var ddl *string
		if err := gormDB.Raw(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, index.Name).Scan(&ddl).Error; err != nil {
			return nil, fmt.Errorf("definition of index %s: %w", index.Name, err)
		}
		var expressions []string
		var where string
		if ddl != nil {
			var rest string
			expressions, rest = splitDefinition(normalizeSQL(*ddl))
			where = strings.TrimSpace(strings.TrimPrefix(rest, "where "))
		}

		parts := make([]string, len(columns))
		for i, column := range columns {
			switch {
			case column.Name != nil:
				parts[i] = normalizeSQL(*column.Name)
			case i < len(expressions):
				parts[i] = trailingOrdering.ReplaceAllString(expressions[i], "")
			default:
				return nil, fmt.Errorf("index %s: expression %d not found in its definition", index.Name, i)
			}
			if column.Desc {
				parts[i] += " desc"
			}
			parts[i] += " collate " + strings.ToLower(column.Coll)
		}
		definition := fmt.Sprintf("%s unique=%t (%s)", index.Origin, index.Unique, strings.Join(parts, ","))
		if where != "" {
			definition += " where " + where
		}
		name := index.Name
		if index.Origin != "c" {
			name = ""
		}
		schemas = append(schemas, IndexSchema{Name: name, Definition: definition})
	}
	return schemas, nil
}

type columnExtras struct {
	collation     string
	autoincrement bool
}

var (
	collateClause    = regexp.MustCompile(`\bcollate (\w+)`)
	trailingOrdering = regexp.MustCompile(`( collate \w+)?( asc| desc)?( collate \w+)?$`)
	autoincrementTok = regexp.MustCompile(`\bautoincrement\b`)
)

// parseColumnDefinitions extracts the CHECK expressions of a normalised
// CREATE TABLE body and the clauses of each column definition that no pragma
// reports. Table constraints other than CHECK are covered by the pragmas.
func parseColumnDefinitions(items []string) (checks []string, columns map[string]columnExtras) {
	columns = map[string]columnExtras{}
	for _, item := range items {
		item = strings.TrimPrefix(item, "constraint ")
		if rest, ok := strings.CutPrefix(item, "check"); ok {
			checks = append(checks, balancedBody(rest)...)
			continue
		}
		if isTableConstraint(item) {
			continue
		}
		name, rest, _ := strings.Cut(item, " ")
		extras := columnExtras{autoincrement: autoincrementTok.MatchString(rest)}
		if match := collateClause.FindStringSubmatch(rest); match != nil {
			extras.collation = match[1]
		}
		columns[name] = extras
		checks = append(checks, checkExpressions(rest)...)
	}
	return checks, columns
}

func isTableConstraint(item string) bool {
	for _, prefix := range []string{"primary key", "unique", "foreign key"} {
		if strings.HasPrefix(item, prefix) {
			return true
		}
	}
	return false
}

// checkExpressions returns the bodies of every check(...) clause of a column definition.
func checkExpressions(definition string) []string {
	var expressions []string
	for rest := definition; ; {
		_, after, found := strings.Cut(rest, "check(")
		if !found {
			return expressions
		}
		bodies := balancedBody("(" + after)
		expressions = append(expressions, bodies...)
		rest = after
	}
}

// balancedBody returns the content of the parenthesised group the text starts with.
func balancedBody(text string) []string {
	items, _ := splitDefinition(text)
	if len(items) == 0 {
		return nil
	}
	return []string{strings.Join(items, ",")}
}

// splitDefinition splits the first parenthesised group of a normalised DDL
// statement at its top-level commas and returns the text following the group.
func splitDefinition(statement string) (items []string, rest string) {
	depth := 0
	start := -1
	inLiteral := false
	for i := 0; i < len(statement); i++ {
		c := statement[i]
		if inLiteral {
			if c == '\'' {
				inLiteral = false
			}
			continue
		}
		switch c {
		case '\'':
			inLiteral = true
		case '(':
			depth++
			if depth == 1 {
				start = i + 1
			}
		case ',':
			if depth == 1 {
				items = append(items, strings.TrimSpace(statement[start:i]))
				start = i + 1
			}
		case ')':
			depth--
			if depth == 0 {
				items = append(items, strings.TrimSpace(statement[start:i]))
				return items, strings.TrimSpace(statement[i+1:])
			}
		}
	}
	return items, ""
}

const (
	tightBefore = "(),<>=!+-*/|%&"
	tightAfter  = "(,<>=!+-*/|%&"
)

// normalizeSQL lowercases a SQL fragment outside string literals, drops
// identifier quotes and collapses whitespace so equivalent spellings compare equal.
func normalizeSQL(statement string) string {
	var b strings.Builder
	inLiteral := false
	pendingSpace := false
	var last rune
	for _, r := range statement {
		if inLiteral {
			b.WriteRune(r)
			inLiteral = r != '\''
			continue
		}
		switch r {
		case '`', '"':
			continue
		case ' ', '\t', '\n', '\r':
			pendingSpace = true
			continue
		}
		if pendingSpace && last != 0 && !strings.ContainsRune(tightBefore, r) && !strings.ContainsRune(tightAfter, last) {
			b.WriteByte(' ')
		}
		pendingSpace = false
		inLiteral = r == '\''
		last = r
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
