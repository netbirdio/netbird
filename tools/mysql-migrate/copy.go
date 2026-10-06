package main

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type dialect struct {
	quote        func(string) string
	tablesQuery  string
	columnsQuery string
}

var mysqlDialect = dialect{
	quote:        func(name string) string { return "`" + name + "`" },
	tablesQuery:  `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE'`,
	columnsQuery: `SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?`,
}

var sqliteDialect = dialect{
	quote:        func(name string) string { return `"` + name + `"` },
	tablesQuery:  `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
	columnsQuery: `SELECT name FROM pragma_table_info(?)`,
}

type column struct {
	name   string
	pgType string
}

// copyStore copies the tables the source shares with the target schema;
// source-only tables are legacy and skipped.
func copyStore(ctx context.Context, src *sql.DB, d dialect, tx pgx.Tx, skip map[string]bool) (int, int64, error) {
	srcTables, err := queryStrings(ctx, src, d.tablesQuery)
	if err != nil {
		return 0, 0, fmt.Errorf("list source tables: %w", err)
	}
	dstTables, err := pgStrings(ctx, tx, `SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	if err != nil {
		return 0, 0, fmt.Errorf("list target tables: %w", err)
	}

	var tables []string
	for _, t := range srcTables {
		if !skip[t] && slices.Contains(dstTables, t) {
			tables = append(tables, t)
		}
	}
	if len(tables) == 0 {
		return 0, 0, fmt.Errorf("no NetBird tables found in the source")
	}

	ordered, err := parentsFirst(ctx, tx, tables)
	if err != nil {
		return 0, 0, err
	}

	var total int64
	for _, table := range ordered {
		n, err := copyTable(ctx, src, d, tx, table)
		if err != nil {
			return 0, 0, fmt.Errorf("table %s: %w", table, err)
		}
		total += n
	}

	if err := resetSequences(ctx, tx, tables); err != nil {
		return 0, 0, err
	}
	return len(tables), total, nil
}

func copyTable(ctx context.Context, src *sql.DB, d dialect, tx pgx.Tx, table string) (int64, error) {
	cols, err := targetColumns(ctx, tx, table)
	if err != nil {
		return 0, err
	}
	srcCols, err := queryStrings(ctx, src, d.columnsQuery, table)
	if err != nil {
		return 0, fmt.Errorf("list source columns: %w", err)
	}

	names := make([]string, len(cols))
	quoted := make([]string, len(cols))
	var missing []string
	for i, c := range cols {
		names[i] = c.name
		quoted[i] = d.quote(c.name)
		if !slices.Contains(srcCols, c.name) {
			missing = append(missing, c.name)
		}
	}
	if len(missing) > 0 {
		return 0, fmt.Errorf("source lacks columns %v; start the management server once with this release before migrating", missing)
	}

	var hasRows bool
	if err := tx.QueryRow(ctx, fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s)", pgx.Identifier{table}.Sanitize())).Scan(&hasRows); err != nil {
		return 0, err
	}
	if hasRows {
		return 0, fmt.Errorf("target already holds data")
	}

	rows, err := src.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s", strings.Join(quoted, ", "), d.quote(table)))
	if err != nil {
		return 0, fmt.Errorf("read source: %w", err)
	}
	defer rows.Close()

	return tx.CopyFrom(ctx, pgx.Identifier{table}, names, newRowSource(rows, cols))
}

func targetColumns(ctx context.Context, tx pgx.Tx, table string) ([]column, error) {
	rows, err := tx.Query(ctx, `SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position`, table)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (column, error) {
		var c column
		err := row.Scan(&c.name, &c.pgType)
		return c, err
	})
}

func parentsFirst(ctx context.Context, tx pgx.Tx, tables []string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT child.relname, parent.relname FROM pg_constraint c
		JOIN pg_class child ON child.oid = c.conrelid
		JOIN pg_class parent ON parent.oid = c.confrelid
		JOIN pg_namespace n ON n.oid = child.relnamespace
		WHERE c.contype = 'f' AND n.nspname = current_schema()`)
	if err != nil {
		return nil, fmt.Errorf("read foreign keys: %w", err)
	}
	parents := map[string][]string{}
	var child, parent string
	_, err = pgx.ForEachRow(rows, []any{&child, &parent}, func() error {
		if child != parent {
			parents[child] = append(parents[child], parent)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read foreign keys: %w", err)
	}

	pending := slices.Sorted(slices.Values(tables))
	done := make(map[string]bool, len(tables))
	ordered := make([]string, 0, len(tables))
	for len(pending) > 0 {
		var next []string
		for _, t := range pending {
			if ready(parents[t], tables, done) {
				ordered = append(ordered, t)
				done[t] = true
			} else {
				next = append(next, t)
			}
		}
		if len(next) == len(pending) {
			return nil, fmt.Errorf("foreign keys form a cycle between %v", next)
		}
		pending = next
	}
	return ordered, nil
}

func ready(parents, tables []string, done map[string]bool) bool {
	for _, p := range parents {
		if slices.Contains(tables, p) && !done[p] {
			return false
		}
	}
	return true
}

// resetSequences moves serial sequences past the ids COPY inserted explicitly.
func resetSequences(ctx context.Context, tx pgx.Tx, tables []string) error {
	rows, err := tx.Query(ctx, `SELECT table_name, column_name, pg_get_serial_sequence(quote_ident(table_name), column_name)
		FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = ANY($1)
		AND pg_get_serial_sequence(quote_ident(table_name), column_name) IS NOT NULL`, tables)
	if err != nil {
		return fmt.Errorf("list sequences: %w", err)
	}
	type sequence struct{ table, column, name string }
	seqs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (sequence, error) {
		var s sequence
		err := row.Scan(&s.table, &s.column, &s.name)
		return s, err
	})
	if err != nil {
		return fmt.Errorf("list sequences: %w", err)
	}

	for _, s := range seqs {
		q := fmt.Sprintf("SELECT setval('%s', COALESCE(MAX(%s), 0) + 1, false) FROM %s",
			strings.ReplaceAll(s.name, "'", "''"), pgx.Identifier{s.column}.Sanitize(), pgx.Identifier{s.table}.Sanitize())
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("reset sequence %s: %w", s.name, err)
		}
	}
	return nil
}

type rowSource struct {
	rows *sql.Rows
	cols []column
	vals []any
	ptrs []any
}

func newRowSource(rows *sql.Rows, cols []column) *rowSource {
	r := &rowSource{rows: rows, cols: cols, vals: make([]any, len(cols)), ptrs: make([]any, len(cols))}
	for i := range r.vals {
		r.ptrs[i] = &r.vals[i]
	}
	return r
}

func (r *rowSource) Next() bool { return r.rows.Next() }

func (r *rowSource) Err() error { return r.rows.Err() }

func (r *rowSource) Values() ([]any, error) {
	if err := r.rows.Scan(r.ptrs...); err != nil {
		return nil, err
	}
	out := make([]any, len(r.vals))
	for i, v := range r.vals {
		if v == nil {
			continue
		}
		converted, err := convert(v, r.cols[i].pgType)
		if err != nil {
			return nil, fmt.Errorf("column %s: %w", r.cols[i].name, err)
		}
		out[i] = converted
	}
	return out, nil
}

// convert adapts a non-NULL value to the target column type: MySQL and SQLite
// return text and numbers as bytes and booleans as integers.
func convert(v any, pgType string) (any, error) {
	switch pgType {
	case "boolean":
		switch b := v.(type) {
		case int64:
			return b != 0, nil
		case []byte:
			return strconv.ParseBool(string(b))
		case string:
			return strconv.ParseBool(b)
		}
	case "bytea":
		if s, ok := v.(string); ok {
			return []byte(s), nil
		}
	case "smallint", "integer", "bigint":
		switch n := v.(type) {
		case uint64:
			if n > math.MaxInt64 {
				return nil, fmt.Errorf("value %d overflows bigint", n)
			}
			return int64(n), nil
		case []byte:
			return strconv.ParseInt(string(n), 10, 64)
		}
	case "real", "double precision":
		if b, ok := v.([]byte); ok {
			return strconv.ParseFloat(string(b), 64)
		}
	case "numeric":
		var s string
		switch x := v.(type) {
		case []byte:
			s = string(x)
		case string:
			s = x
		default:
			return v, nil
		}
		var n pgtype.Numeric
		if err := n.Scan(s); err != nil {
			return nil, err
		}
		return n, nil
	default:
		if b, ok := v.([]byte); ok {
			return string(b), nil
		}
	}
	return v, nil
}

func queryStrings(ctx context.Context, db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func pgStrings(ctx context.Context, tx pgx.Tx, query string) ([]string, error) {
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
