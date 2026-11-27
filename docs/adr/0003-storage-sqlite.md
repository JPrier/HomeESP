# ADR 0003: SQLite WAL, single writer, histogram rollups

**Status:** accepted · 2026-11-26

One SQLite file in WAL mode with foreign keys and versioned migrations. All writes go
through one dedicated thread (in order, transactional); queries use separate read-only
connections so API load never blocks intake. Probe rollups store mergeable log-scale
histograms per minute (compacted to hours), so percentiles are never averaged. Raw rows
are retained 7 days by default; retention runs in bounded batches. Backups use the
SQLite online backup API. Measured footprint is in the test report.
