-- ========================================================
-- SAZON - ESQUEMA DE BASE DE DATOS PARA CLOUDFLARE D1
-- Base de datos: sazon-db (2bb8986a-335f-4c9b-9233-dc16f24b92a3)
-- ========================================================

-- 1. USUARIOS
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT UNIQUE NOT NULL,
    pin_hash TEXT DEFAULT '',
    role TEXT NOT NULL CHECK(role IN ('ADMIN', 'MOZO', 'ANFITRIONA')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2. PRODUCTOS
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL DEFAULT 0.0,
    target_role TEXT NOT NULL DEFAULT 'MOZO' CHECK(target_role IN ('ALL', 'MOZO', 'ANFITRIONA')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 3. VENTAS
CREATE TABLE IF NOT EXISTS sales (
    id TEXT PRIMARY KEY,
    sale_date TEXT NOT NULL,
    product_id TEXT NOT NULL REFERENCES products(id),
    worker_id TEXT NOT NULL REFERENCES users(id),
    created_by_id TEXT NOT NULL REFERENCES users(id),
    quantity REAL NOT NULL DEFAULT 1,
    unit_price REAL NOT NULL,
    total REAL NOT NULL,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(sale_date);
CREATE INDEX IF NOT EXISTS idx_sales_worker ON sales(worker_id);
CREATE INDEX IF NOT EXISTS idx_sales_product ON sales(product_id);

-- 4. METAS FINANCIERAS DE TIENDA (MENSUAL Y DIARIA)
CREATE TABLE IF NOT EXISTS store_targets (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    day INTEGER,
    target_amount REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(period_month, day)
);

CREATE INDEX IF NOT EXISTS idx_store_targets_period ON store_targets(period_month);

-- 5. METAS POR PRODUCTO (GENERALES O POR TRABAJADOR)
CREATE TABLE IF NOT EXISTS product_goals (
    id TEXT PRIMARY KEY,
    period_month TEXT NOT NULL,
    product_id TEXT NOT NULL REFERENCES products(id),
    worker_id TEXT REFERENCES users(id),
    target_quantity REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(period_month, product_id, worker_id)
);

CREATE INDEX IF NOT EXISTS idx_product_goals_period ON product_goals(period_month);

-- 6. PROMOCIONES
CREATE TABLE IF NOT EXISTS promotions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    start_date TEXT NOT NULL,
    end_date TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK(target_type IN ('ALL', 'ROLE', 'WORKER')),
    target_role TEXT CHECK(target_role IN ('MOZO', 'ANFITRIONA')),
    target_worker_id TEXT REFERENCES users(id),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 7. TAREAS
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    deadline TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 8. ASIGNACIÓN Y ESTADO DE TAREAS POR TRABAJADOR
CREATE TABLE IF NOT EXISTS task_assignees (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    completed INTEGER NOT NULL DEFAULT 0,
    completed_at TEXT,
    observations TEXT,
    PRIMARY KEY (task_id, user_id)
);

-- 9. EVENTOS Y CRONOGRAMAS
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    event_date TEXT NOT NULL,
    event_time TEXT NOT NULL,
    event_type TEXT DEFAULT 'REUNION',
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS event_participants (
    event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (event_id, user_id)
);

-- 10. AUDIT LOG (REGISTRO DE AUDITORÍA)
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_id TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);

-- ========================================================
-- DATOS INICIALES REALES DE SAZÓN
-- ========================================================

-- Usuarios: 1 Administrador y 10 Mozos preexistentes
INSERT OR IGNORE INTO users (id, name, code, pin_hash, role) VALUES
('ad1', 'Administrador', '2580', 'ed946f65d2c785d90e827c5ffd879ce3b49c68d4c88013074176a7e73bc58bcf', 'ADMIN'),
('w1', 'Gustavo Almonacid', '1001', 'fe675fe7aaee830b6fed09b64e034f84dcbdaeb429d9cccd4ebb90e15af8dd71', 'MOZO'),
('w2', 'Alessandra', '1002', 'b281bc2c616cb3c3a097215fdc9397ae87e6e06b156cc34e656be7a1a9ce8839', 'MOZO'),
('w3', 'Wilmer Gomez', '1003', '8c9a013ab70c0434313e3e881c310b9ff24aff1075255ceede3f2c239c231623', 'MOZO'),
('w4', 'Jorge Guevara', '1004', '75992a5ac67ff644d3063976c2effd10bdd93fcc109798e3d5c1acf2e530d01a', 'MOZO'),
('w5', 'Maicol Cordova', '1005', '7f861bcee185de001377d79e08af62e94b1e7718e2470e08520c917f8d953602', 'MOZO'),
('w6', 'Nicol', '1006', '478c4ffb1cbcea37956a748e6c19d8eadd0a47e86f5e308d26cad39453b5d1ab', 'MOZO'),
('w7', 'Sarela Pucho', '1007', '2c8b871e52d4e5f5db5ff84a82a45327e20df77edef961c4b6fa0e9c3d97ce5b', 'MOZO'),
('w8', 'Yovana Espinoza', '1008', '9aaf689fbcdfe9f64a071f9cbe28ae44193fa218e72af24456f44bed64583b4d', 'MOZO'),
('w9', 'Selene', '1009', '6ad4a6b1e5ea5569795e516d71909e0ce4809d9dc983d2c219144f684f816e12', 'MOZO'),
('w10', 'Marcelo', '1010', '7a5df5ffa0dec2228d90b8d0a0f1b0767b748b0a41314c123075b8289e4e053f', 'MOZO');

-- Catálogo de productos rentables
INSERT OR IGNORE INTO products (id, name, category, price, target_role) VALUES
('mp0', '1/4 Pollo', 'POLLOS', 22.0, 'MOZO'),
('mp1', 'Bife', 'PARRILLAS', 38.0, 'MOZO'),
('mp2', 'Champiñones', 'ENTRADAS', 24.0, 'MOZO'),
('mp3', 'Picaña', 'PARRILLAS', 42.0, 'MOZO'),
('mp4', 'Lomo', 'PARRILLAS', 40.0, 'MOZO'),
('mp5', 'Tequeños', 'ENTRADAS', 18.0, 'MOZO'),
('mp6', 'Bondiola', 'PARRILLAS', 32.0, 'MOZO'),
('mp7', 'Tragos', 'BEBIDAS', 25.0, 'MOZO'),
('mp8', 'Bebidas', 'BEBIDAS', 10.0, 'MOZO'),
('mp9', 'Happy Hour', 'BEBIDAS', 35.0, 'MOZO'),
('mp10', 'Postres', 'POSTRES', 16.0, 'MOZO'),
('mp11', 'Frozen', 'BEBIDAS', 14.0, 'MOZO');

-- Proyección de tienda mensual base
INSERT OR IGNORE INTO store_targets (id, period_month, day, target_amount) VALUES
('st_2026-09_month', '2026-09', NULL, 350000.0);

-- Metas de tienda para productos
INSERT OR IGNORE INTO product_goals (id, period_month, product_id, worker_id, target_quantity) VALUES
('pg_2026-09_mp0_store', '2026-09', 'mp0', NULL, 2000.0),
('pg_2026-09_mp1_store', '2026-09', 'mp1', NULL, 400.0),
('pg_2026-09_mp2_store', '2026-09', 'mp2', NULL, 400.0),
('pg_2026-09_mp3_store', '2026-09', 'mp3', NULL, 400.0),
('pg_2026-09_mp4_store', '2026-09', 'mp4', NULL, 400.0),
('pg_2026-09_mp5_store', '2026-09', 'mp5', NULL, 400.0),
('pg_2026-09_mp6_store', '2026-09', 'mp6', NULL, 400.0),
('pg_2026-09_mp7_store', '2026-09', 'mp7', NULL, 400.0),
('pg_2026-09_mp8_store', '2026-09', 'mp8', NULL, 400.0),
('pg_2026-09_mp9_store', '2026-09', 'mp9', NULL, 400.0),
('pg_2026-09_mp10_store', '2026-09', 'mp10', NULL, 400.0),
('pg_2026-09_mp11_store', '2026-09', 'mp11', NULL, 400.0);
