package migration

const migration = `
create or replace function bitmap_to_bitarray(int)
returns int[]
language sql
immutable
security invoker
parallel safe
cost 0.01
as $$
  select array(select (1 << s) from generate_series(0, 31) as s
  where (1 << s) & $1 > 0)
$$
;

create index if not exists name_idx_1 on users
  using gin (
    bitmap_to_bitarray(name_hash_1)
  );
create index if not exists name_idx_2 on users
  using gin (
    bitmap_to_bitarray(name_hash_2)
  );
create index if not exists name_idx_3 on users
  using gin (
    bitmap_to_bitarray(name_hash_3)
  );
create index if not exists name_idx_4 on users
  using gin (
    bitmap_to_bitarray(name_hash_4)
  );
create index if not exists name_idx_5 on users
  using gin (
    bitmap_to_bitarray(name_hash_5)
  );
create index if not exists name_idx_6 on users
  using gin (
    bitmap_to_bitarray(name_hash_6)
  );
`

// func CreateFuzzySearchIndex(ctx context.Context, db *gorm.DB) error {
// 	if err := db.Transaction(func(tx *gorm.DB) error {

// 		users := make([]*types.User, 0)
// 		if err := tx.Where("name <> ''").Find(&users).Error; err != nil {
// 			return fmt.Errorf("error fetching users", err)
// 		}

// 		// check the engine
// 		if err := tx.Exec(migration).Error; err != nil {
// 			return fmt.Errorf("error adding user name fuzzy search indexes", err)
// 		}

// 		return nil
// 	}); err != nil {
// 		return err
// 	}
// }
