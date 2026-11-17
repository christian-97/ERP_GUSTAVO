-- ========================================================
-- MIGRACIÓN SAZON D1 V2 (Tablas y extensiones seguras)
-- ========================================================

CREATE TABLE IF NOT EXISTS worker_monthly_records (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    worker_id TEXT NOT NULL REFERENCES users(id),
    support_pollos REAL DEFAULT 0.0,
    cash_achieved REAL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(period_month, worker_id)
);
CREATE INDEX IF NOT EXISTS idx_wmr_period ON worker_monthly_records(period_month);

CREATE TABLE IF NOT EXISTS store_monthly_records (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL UNIQUE,
    accumulated_sales REAL DEFAULT 0.0,
    monthly_target REAL DEFAULT 0.0,
    total_store_pollos REAL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS store_product_records (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    product_id TEXT NOT NULL REFERENCES products(id),
    target_units REAL DEFAULT 0.0,
    actual_units REAL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(period_month, product_id)
);
CREATE INDEX IF NOT EXISTS idx_spr_period ON store_product_records(period_month);

CREATE TABLE IF NOT EXISTS daily_projections (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    day INTEGER NOT NULL,
    projected_amount REAL DEFAULT 0.0,
    actual_amount REAL DEFAULT 0.0,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(period_month, day)
);
CREATE INDEX IF NOT EXISTS idx_dp_period ON daily_projections(period_month);

CREATE TABLE IF NOT EXISTS worker_comments (
    id TEXT PRIMARY KEY,
    worker_id TEXT NOT NULL REFERENCES users(id),
    period_month TEXT NOT NULL,
    author_id TEXT NOT NULL REFERENCES users(id),
    comment TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_wc_worker_period ON worker_comments(worker_id, period_month);
