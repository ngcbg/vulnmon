# SQL migrations

The executable schema is the ordered migration set in [src/vulnmon/correlatord/persistence/migrations/](../src/vulnmon/correlatord/persistence/migrations/). It is packaged with the application, so installed and source execution use the same SQL. Do not maintain a second copy.

Rules:

- **Naming.** Files are named `NNNN_description.sql`, numbered contiguously from `0001`. `PRAGMA user_version` records the last migration applied.
- **One transaction each.** `vulnctl init` (`Store.migrate()`) applies each pending migration in its own `BEGIN IMMEDIATE` transaction, together with the `user_version` update. A failing migration rolls back completely.
- **No transaction statements in migration files.** Files must not contain `BEGIN`, `COMMIT`, `SAVEPOINT` or similar; the runner refuses them.
- **Applied migrations are immutable.** Never edit one. Add a new migration that preserves existing data.
- **Version checks.** All other operations refuse a database whose schema is older than the code ("run init") or newer than the code. Migration is never automatic. Before migrating a production database, take a SQLite-aware backup (architecture §9.7).
- **Old databases.** `0001_initial.sql` is the former `schema.sql`. Databases created by earlier prototype versions are already at version 1.
