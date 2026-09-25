/**
 * SAZON - Cloudflare Worker API REST
 * Backend exclusivo para sazon-db
 */
import HTML from '../index.html';

const DEFAULT_SECRET = 'sazon_d1_jwt_key_2026_super_secure';

// ===================================================================
// CORS HELPERS
// ===================================================================
function getCorsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = [
    'https://christian-97.github.io',
    'http://localhost',
    'http://127.0.0.1'
  ];
  const isAllowed = allowed.some(a => origin === a || origin.startsWith(a + ':')) || origin === 'null';
  const allowOrigin = isAllowed ? origin : 'https://christian-97.github.io';

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Max-Age': '86400'
  };
}

function jsonResponse(data, status = 200, request = null) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    ...(request ? getCorsHeaders(request) : { 'Access-Control-Allow-Origin': '*' })
  };
  return new Response(JSON.stringify(data), { status, headers });
}

function errorResponse(message, status = 400, request = null) {
  return jsonResponse({ ok: false, error: message }, status, request);
}

// ===================================================================
// CRYPTO HELPERS (Web Crypto)
// ===================================================================
async function sha256(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function signToken(payload, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret || DEFAULT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const payloadStr = btoa(JSON.stringify({ ...payload, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }));
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(payloadStr));
  const sigHex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${payloadStr}.${sigHex}`;
}

async function verifyToken(token, secret) {
  if (!token || !token.includes('.')) return null;
  try {
    const [payloadStr, sigHex] = token.split('.');
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret || DEFAULT_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    const sigBytes = new Uint8Array(sigHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(payloadStr));
    if (!valid) return null;
    const payload = JSON.parse(atob(payloadStr));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

async function authenticate(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.substring(7).trim();
  return await verifyToken(token, env.JWT_SECRET || DEFAULT_SECRET);
}

// ===================================================================
// AUDIT LOG
// ===================================================================
async function logAudit(db, userId, action, entity, entityId, details) {
  try {
    await db.prepare(
      `INSERT INTO audit_log (id, user_id, action, entity, entity_id, details)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      'aud_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6),
      userId, action, entity, entityId, JSON.stringify(details || {})
    ).run();
  } catch (e) {
    console.error('Error logging audit:', e);
  }
}

// ===================================================================
// MAIN WORKER HANDLER
// ===================================================================
export default {
  async fetch(request, env) {
    // 1. CORS Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(request)
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // ===============================================================
    // 2. SERVIR EL FRONTEND ESTÁTICO (index.html) PARA RUTAS NO-API
    // ===============================================================
    if (!path.startsWith('/api/')) {
      if (method === 'GET') {
        return new Response(HTML, {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache'
          }
        });
      }
      return new Response('Not Found', { status: 404 });
    }

    const db = env.DB;
    if (!db) {
      return errorResponse('D1 Database binding (DB) no configurado.', 500, request);
    }

    // ===============================================================
    // 3. RUTAS PÚBLICAS DE LA API (/api/*)
    // ===============================================================
    // HEALTH CHECK
    if (path === '/api/health' && method === 'GET') {
      return jsonResponse({
        ok: true,
        service: 'sazon-api',
        time: new Date().toISOString()
      }, 200, request);
    }

    // ===============================================================
    // AUTH: LOGIN (Solo con Código de Empleado)
    // ===============================================================
    if (path === '/api/auth/login' && method === 'POST') {
      try {
        const body = await request.json();
        const code = (body.code || '').trim();

        if (!code) return errorResponse('Ingresa tu código de empleado.', 400, request);

        const user = await db.prepare(
          'SELECT id, name, code, role, active FROM users WHERE code = ?'
        ).bind(code).first();

        if (!user || user.active === 0) {
          return errorResponse('Código de empleado no reconocido.', 401, request);
        }

        const token = await signToken(
          { id: user.id, name: user.name, role: user.role, code: user.code },
          env.JWT_SECRET
        );

        return jsonResponse({
          ok: true,
          token,
          user: {
            id: user.id,
            name: user.name,
            code: user.code,
            role: user.role
          }
        }, 200, request);
      } catch (e) {
        return errorResponse('Error procesando login: ' + e.message, 500, request);
      }
    }

    // Endpoints protegidos a continuación
    const auth = await authenticate(request, env);
    if (!auth) {
      return errorResponse('No autorizado. Token inválido o ausente.', 401, request);
    }

    const isAdmin = auth.role === 'ADMIN';

    // ===============================================================
    // USUARIOS
    // ===============================================================
    if (path === '/api/users' && method === 'GET') {
      const { results } = await db.prepare(
        'SELECT id, name, code, role, active, created_at FROM users ORDER BY role ASC, name ASC'
      ).all();
      return jsonResponse({ ok: true, users: results }, 200, request);
    }

    if (path === '/api/users' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      try {
        const b = await request.json();
        const name = (b.name || '').trim();
        const code = (b.code || '').trim();
        const role = (b.role || 'MOZO').toUpperCase();

        if (!name || !code) return errorResponse('Nombre y código son requeridos.', 400, request);
        if (!['ADMIN', 'MOZO', 'ANFITRIONA'].includes(role)) return errorResponse('Rol no válido.', 400, request);

        const existing = await db.prepare('SELECT id FROM users WHERE code = ?').bind(code).first();
        if (existing) return errorResponse('Ese código ya está en uso.', 400, request);

        const id = (role === 'ADMIN' ? 'ad' : 'w') + Date.now();

        await db.prepare(
          'INSERT INTO users (id, name, code, pin_hash, role, active) VALUES (?, ?, ?, ?, ?, 1)'
        ).bind(id, name, code, '', role).run();

        await logAudit(db, auth.id, 'CREATE_USER', 'users', id, { name, code, role });

        return jsonResponse({ ok: true, user: { id, name, code, role, active: 1 } }, 201, request);
      } catch (e) {
        return errorResponse('Error creando usuario: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/users/') && method === 'PUT') {
      const targetId = path.split('/')[3];
      // El trabajador puede editar su propio perfil; el admin puede editar cualquiera
      if (!isAdmin && auth.id !== targetId) {
        return errorResponse('Permiso denegado.', 403, request);
      }
      try {
        const b = await request.json();
        const currentUser = await db.prepare('SELECT * FROM users WHERE id = ?').bind(targetId).first();
        if (!currentUser) return errorResponse('Usuario no encontrado.', 404, request);

        const name = b.name !== undefined ? b.name.trim() : currentUser.name;
        const code = b.code !== undefined ? b.code.trim() : currentUser.code;
        const role = (isAdmin && b.role) ? b.role.toUpperCase() : currentUser.role;
        const active = (isAdmin && b.active !== undefined) ? (b.active ? 1 : 0) : currentUser.active;

        if (code !== currentUser.code) {
          const duplicate = await db.prepare('SELECT id FROM users WHERE code = ? AND id != ?').bind(code, targetId).first();
          if (duplicate) return errorResponse('El código ya está en uso por otro usuario.', 400, request);
        }

        await db.prepare(
          'UPDATE users SET name = ?, code = ?, role = ?, active = ? WHERE id = ?'
        ).bind(name, code, role, active, targetId).run();

        await logAudit(db, auth.id, 'UPDATE_USER', 'users', targetId, { name, code, role, active });

        return jsonResponse({ ok: true, user: { id: targetId, name, code, role, active } }, 200, request);
      } catch (e) {
        return errorResponse('Error actualizando usuario: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // PRODUCTOS
    // ===============================================================
    if (path === '/api/products' && method === 'GET') {
      const activeOnly = url.searchParams.get('all') !== 'true';
      const query = activeOnly
        ? 'SELECT * FROM products WHERE active = 1 ORDER BY category ASC, name ASC'
        : 'SELECT * FROM products ORDER BY category ASC, name ASC';
      const { results } = await db.prepare(query).all();
      return jsonResponse({ ok: true, products: results }, 200, request);
    }

    if (path === '/api/products' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      try {
        const b = await request.json();
        const name = (b.name || '').trim();
        const category = (b.category || 'GENERAL').toUpperCase().trim();
        const price = parseFloat(b.price) || 0.0;
        const target_role = (b.target_role || 'MOZO').toUpperCase();

        if (!name) return errorResponse('Nombre del producto es requerido.', 400, request);
        const id = 'mp_' + Date.now();

        await db.prepare(
          'INSERT INTO products (id, name, category, price, target_role, active) VALUES (?, ?, ?, ?, ?, 1)'
        ).bind(id, name, category, price, target_role).run();

        await logAudit(db, auth.id, 'CREATE_PRODUCT', 'products', id, { name, category, price, target_role });

        return jsonResponse({ ok: true, product: { id, name, category, price, target_role, active: 1 } }, 201, request);
      } catch (e) {
        return errorResponse('Error creando producto: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/products/') && method === 'PUT') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      const prodId = path.split('/')[3];
      try {
        const b = await request.json();
        const current = await db.prepare('SELECT * FROM products WHERE id = ?').bind(prodId).first();
        if (!current) return errorResponse('Producto no encontrado.', 404, request);

        const name = b.name !== undefined ? b.name.trim() : current.name;
        const category = b.category !== undefined ? b.category.toUpperCase().trim() : current.category;
        const price = b.price !== undefined ? parseFloat(b.price) : current.price;
        const target_role = b.target_role !== undefined ? b.target_role.toUpperCase() : current.target_role;
        const active = b.active !== undefined ? (b.active ? 1 : 0) : current.active;

        await db.prepare(
          'UPDATE products SET name = ?, category = ?, price = ?, target_role = ?, active = ? WHERE id = ?'
        ).bind(name, category, price, target_role, active, prodId).run();

        await logAudit(db, auth.id, 'UPDATE_PRODUCT', 'products', prodId, { name, category, price, active });

        return jsonResponse({ ok: true, product: { id: prodId, name, category, price, target_role, active } }, 200, request);
      } catch (e) {
        return errorResponse('Error actualizando producto: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // VENTAS
    // ===============================================================
    if (path === '/api/sales' && method === 'GET') {
      const month = url.searchParams.get('month'); // YYYY-MM
      const date = url.searchParams.get('date');   // YYYY-MM-DD
      const workerParam = url.searchParams.get('worker_id');

      // Restricción de permisos: si no es admin, solo ve sus propias ventas
      const filterWorker = (!isAdmin) ? auth.id : workerParam;

      let sql = `
        SELECT s.*, p.name as product_name, p.category as product_category,
               w.name as worker_name, c.name as created_by_name
        FROM sales s
        JOIN products p ON s.product_id = p.id
        JOIN users w ON s.worker_id = w.id
        JOIN users c ON s.created_by_id = c.id
        WHERE 1=1
      `;
      const params = [];

      if (date) {
        sql += ' AND s.sale_date = ?';
        params.push(date);
      } else if (month) {
        sql += ' AND s.sale_date LIKE ?';
        params.push(`${month}%`);
      }

      if (filterWorker) {
        sql += ' AND s.worker_id = ?';
        params.push(filterWorker);
      }

      sql += ' ORDER BY s.created_at DESC';

      const stmt = db.prepare(sql);
      const { results } = params.length > 0 ? await stmt.bind(...params).all() : await stmt.all();

      return jsonResponse({ ok: true, sales: results }, 200, request);
    }

    if (path === '/api/sales' && method === 'POST') {
      try {
        const b = await request.json();
        const productId = b.product_id;
        // Permiso de asignación: Si es admin, puede registrar para cualquier trabajador; si es mozo, solo para sí mismo
        const workerId = (isAdmin && b.worker_id) ? b.worker_id : auth.id;
        const createdById = auth.id;
        const quantity = parseFloat(b.quantity) || 1;
        const saleDate = (b.sale_date || new Date().toISOString().split('T')[0]).trim();
        const notes = (b.notes || '').trim();

        if (!productId) return errorResponse('ID de producto requerido.', 400, request);

        // Obtener precio actual del producto si no se envía unit_price
        const product = await db.prepare('SELECT price FROM products WHERE id = ?').bind(productId).first();
        if (!product) return errorResponse('Producto no existe.', 400, request);

        const unitPrice = b.unit_price !== undefined ? parseFloat(b.unit_price) : product.price;
        const total = quantity * unitPrice;
        const id = 'sal_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);

        await db.prepare(
          `INSERT INTO sales (id, sale_date, product_id, worker_id, created_by_id, quantity, unit_price, total, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, saleDate, productId, workerId, createdById, quantity, unitPrice, total, notes).run();

        await logAudit(db, auth.id, 'CREATE_SALE', 'sales', id, { workerId, productId, quantity, total, saleDate });

        return jsonResponse({
          ok: true,
          sale: { id, sale_date: saleDate, product_id: productId, worker_id: workerId, created_by_id: createdById, quantity, unit_price: unitPrice, total, notes }
        }, 201, request);
      } catch (e) {
        return errorResponse('Error registrando venta: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/sales/') && method === 'PUT') {
      if (!isAdmin) return errorResponse('Solo el administrador puede editar ventas registradas.', 403, request);
      const saleId = path.split('/')[3];
      try {
        const b = await request.json();
        const current = await db.prepare('SELECT * FROM sales WHERE id = ?').bind(saleId).first();
        if (!current) return errorResponse('Venta no encontrada.', 404, request);

        const quantity = b.quantity !== undefined ? parseFloat(b.quantity) : current.quantity;
        const unitPrice = b.unit_price !== undefined ? parseFloat(b.unit_price) : current.unit_price;
        const total = quantity * unitPrice;
        const notes = b.notes !== undefined ? b.notes : current.notes;
        const workerId = b.worker_id !== undefined ? b.worker_id : current.worker_id;

        await db.prepare(
          'UPDATE sales SET quantity = ?, unit_price = ?, total = ?, notes = ?, worker_id = ? WHERE id = ?'
        ).bind(quantity, unitPrice, total, notes, workerId, saleId).run();

        await logAudit(db, auth.id, 'UPDATE_SALE', 'sales', saleId, { quantity, total, workerId });

        return jsonResponse({ ok: true, sale: { id: saleId, quantity, unit_price: unitPrice, total, worker_id: workerId, notes } }, 200, request);
      } catch (e) {
        return errorResponse('Error actualizando venta: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // METAS (STORE TARGETS Y PRODUCT GOALS)
    // ===============================================================
    if (path === '/api/goals' && method === 'GET') {
      const now = new Date();
      const currentMonth = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const workerId = url.searchParams.get('worker_id') || (!isAdmin ? auth.id : null);

      const storeTargets = await db.prepare(
        'SELECT * FROM store_targets WHERE period_month = ? ORDER BY day ASC'
      ).bind(currentMonth).all();

      let productGoalsQuery = `
        SELECT pg.*, p.name as product_name, p.category as product_category
        FROM product_goals pg
        JOIN products p ON pg.product_id = p.id
        WHERE pg.period_month = ?
      `;
      const pParams = [currentMonth];

      if (workerId) {
        productGoalsQuery += ' AND (pg.worker_id = ? OR pg.worker_id IS NULL)';
        pParams.push(workerId);
      }

      const productGoals = await db.prepare(productGoalsQuery).bind(...pParams).all();

      return jsonResponse({
        ok: true,
        month: currentMonth,
        storeTargets: storeTargets.results,
        productGoals: productGoals.results
      }, 200, request);
    }

    if (path === '/api/goals' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      try {
        const b = await request.json();
        const type = b.type; // 'STORE_TARGET' o 'PRODUCT_GOAL'
        const periodMonth = b.period_month || `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;

        if (type === 'STORE_TARGET') {
          const day = b.day != null ? parseInt(b.day) : null;
          const targetAmount = parseFloat(b.target_amount) || 0;
          const id = `st_${periodMonth}_${day != null ? day : 'month'}`;

          await db.prepare(
            `INSERT INTO store_targets (id, period_month, day, target_amount)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(period_month, day) DO UPDATE SET target_amount = excluded.target_amount`
          ).bind(id, periodMonth, day, targetAmount).run();

          await logAudit(db, auth.id, 'SET_STORE_TARGET', 'store_targets', id, { periodMonth, day, targetAmount });
          return jsonResponse({ ok: true, id, periodMonth, day, targetAmount }, 200, request);
        } else if (type === 'PRODUCT_GOAL') {
          const productId = b.product_id;
          const workerId = b.worker_id || null;
          const targetQuantity = parseFloat(b.target_quantity) || 0;
          const id = `pg_${periodMonth}_${productId}_${workerId || 'store'}`;

          await db.prepare(
            `INSERT INTO product_goals (id, period_month, product_id, worker_id, target_quantity)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(period_month, product_id, worker_id) DO UPDATE SET target_quantity = excluded.target_quantity`
          ).bind(id, periodMonth, productId, workerId, targetQuantity).run();

          await logAudit(db, auth.id, 'SET_PRODUCT_GOAL', 'product_goals', id, { periodMonth, productId, workerId, targetQuantity });
          return jsonResponse({ ok: true, id, periodMonth, productId, workerId, targetQuantity }, 200, request);
        } else {
          return errorResponse('Tipo de meta desconocido.', 400, request);
        }
      } catch (e) {
        return errorResponse('Error guardando meta: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // PROMOCIONES
    // ===============================================================
    if (path === '/api/promotions' && method === 'GET') {
      let sql = 'SELECT * FROM promotions WHERE active = 1';
      const params = [];

      if (!isAdmin) {
        sql += ' AND (target_type = "ALL" OR (target_type = "ROLE" AND target_role = ?) OR (target_type = "WORKER" AND target_worker_id = ?))';
        params.push(auth.role, auth.id);
      }

      sql += ' ORDER BY start_date DESC';
      const { results } = params.length > 0 ? await db.prepare(sql).bind(...params).all() : await db.prepare(sql).all();
      return jsonResponse({ ok: true, promotions: results }, 200, request);
    }

    if (path === '/api/promotions' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      try {
        const b = await request.json();
        const title = (b.title || '').trim();
        const description = (b.description || '').trim();
        const startDate = b.start_date;
        const endDate = b.end_date;
        const targetType = b.target_type || 'ALL';
        const targetRole = b.target_role || null;
        const targetWorkerId = b.target_worker_id || null;

        if (!title || !startDate || !endDate) return errorResponse('Título y fechas son requeridos.', 400, request);

        const id = 'pro_' + Date.now();
        await db.prepare(
          `INSERT INTO promotions (id, title, description, start_date, end_date, target_type, target_role, target_worker_id, active)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`
        ).bind(id, title, description, startDate, endDate, targetType, targetRole, targetWorkerId).run();

        await logAudit(db, auth.id, 'CREATE_PROMO', 'promotions', id, { title, targetType });

        return jsonResponse({ ok: true, promotion: { id, title, description, startDate, endDate } }, 201, request);
      } catch (e) {
        return errorResponse('Error creando promoción: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/promotions/') && method === 'PUT') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      const promoId = path.split('/')[3];
      try {
        const b = await request.json();
        const active = b.active !== undefined ? (b.active ? 1 : 0) : 1;
        await db.prepare('UPDATE promotions SET active = ? WHERE id = ?').bind(active, promoId).run();
        return jsonResponse({ ok: true, id: promoId, active }, 200, request);
      } catch (e) {
        return errorResponse('Error actualizando promoción: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // TAREAS (CON task_assignees)
    // ===============================================================
    if (path === '/api/tasks' && method === 'GET') {
      let tasksQuery = 'SELECT t.*, u.name as created_by_name FROM tasks t JOIN users u ON t.created_by = u.id ORDER BY t.deadline ASC';
      const { results: allTasks } = await db.prepare(tasksQuery).all();

      // Obtener asignados y completados
      const { results: assignees } = await db.prepare(
        `SELECT ta.*, u.name as worker_name
         FROM task_assignees ta
         JOIN users u ON ta.user_id = u.id`
      ).all();

      const assigneesByTask = {};
      assignees.forEach(a => {
        if (!assigneesByTask[a.task_id]) assigneesByTask[a.task_id] = [];
        assigneesByTask[a.task_id].push(a);
      });

      const tasks = allTasks.map(t => ({
        ...t,
        assignees: assigneesByTask[t.id] || []
      })).filter(t => {
        if (isAdmin) return true;
        // Si es trabajador: tareas sin asignados específicos (para todos) o asignadas a él
        if (t.assignees.length === 0) return true;
        return t.assignees.some(a => a.user_id === auth.id);
      });

      return jsonResponse({ ok: true, tasks }, 200, request);
    }

    if (path === '/api/tasks' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      try {
        const b = await request.json();
        const name = (b.name || '').trim();
        const deadline = b.deadline;
        const assigneeIds = Array.isArray(b.assignees) ? b.assignees : [];

        if (!name || !deadline) return errorResponse('Nombre y fecha límite requeridos.', 400, request);

        const taskId = 'tk_' + Date.now();
        await db.prepare('INSERT INTO tasks (id, name, deadline, created_by) VALUES (?, ?, ?, ?)').bind(taskId, name, deadline, auth.id).run();

        for (const uid of assigneeIds) {
          await db.prepare('INSERT INTO task_assignees (task_id, user_id) VALUES (?, ?)').bind(taskId, uid).run();
        }

        await logAudit(db, auth.id, 'CREATE_TASK', 'tasks', taskId, { name, deadline, assignees: assigneeIds });

        return jsonResponse({ ok: true, task: { id: taskId, name, deadline, assignees: assigneeIds } }, 201, request);
      } catch (e) {
        return errorResponse('Error creando tarea: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/tasks/') && method === 'PUT') {
      const taskId = path.split('/')[3];
      try {
        const b = await request.json();

        // Trabajador marcando tarea como completada/desmarcada
        if (b.action === 'toggle_complete' || b.completed !== undefined) {
          const targetUser = (!isAdmin) ? auth.id : (b.user_id || auth.id);
          const completed = b.completed ? 1 : 0;
          const observations = (b.observations || '').trim();
          const completedAt = completed ? new Date().toISOString() : null;

          await db.prepare(
            `INSERT INTO task_assignees (task_id, user_id, completed, completed_at, observations)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(task_id, user_id) DO UPDATE SET
               completed = excluded.completed,
               completed_at = excluded.completed_at,
               observations = excluded.observations`
          ).bind(taskId, targetUser, completed, completedAt, observations).run();

          return jsonResponse({ ok: true, task_id: taskId, user_id: targetUser, completed, observations }, 200, request);
        }

        // Si el admin modifica el nombre o deadline
        if (isAdmin && (b.name || b.deadline)) {
          const current = await db.prepare('SELECT * FROM tasks WHERE id = ?').bind(taskId).first();
          if (!current) return errorResponse('Tarea no encontrada.', 404, request);
          const name = b.name || current.name;
          const deadline = b.deadline || current.deadline;

          await db.prepare('UPDATE tasks SET name = ?, deadline = ? WHERE id = ?').bind(name, deadline, taskId).run();
          return jsonResponse({ ok: true, task: { id: taskId, name, deadline } }, 200, request);
        }

        return errorResponse('Acción no soportada.', 400, request);
      } catch (e) {
        return errorResponse('Error actualizando tarea: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // EVENTOS Y CRONOGRAMAS
    // ===============================================================
    if (path === '/api/events' && method === 'GET') {
      const { results: events } = await db.prepare(
        'SELECT * FROM events ORDER BY event_date ASC, event_time ASC'
      ).all();

      const { results: participants } = await db.prepare(
        `SELECT ep.*, u.name as user_name
         FROM event_participants ep
         JOIN users u ON ep.user_id = u.id`
      ).all();

      const partMap = {};
      participants.forEach(p => {
        if (!partMap[p.event_id]) partMap[p.event_id] = [];
        partMap[p.event_id].push(p);
      });

      const fullEvents = events.map(e => ({
        ...e,
        participants: partMap[e.id] || []
      }));

      return jsonResponse({ ok: true, events: fullEvents }, 200, request);
    }

    if (path === '/api/events' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      try {
        const b = await request.json();
        const title = (b.title || '').trim();
        const description = (b.description || '').trim();
        const eventDate = b.event_date;
        const eventTime = b.event_time || '10:00';
        const eventType = b.event_type || 'REUNION';
        const participantIds = Array.isArray(b.participants) ? b.participants : [];

        if (!title || !eventDate) return errorResponse('Título y fecha son requeridos.', 400, request);

        const id = 'ev_' + Date.now();
        await db.prepare(
          'INSERT INTO events (id, title, description, event_date, event_time, event_type, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).bind(id, title, description, eventDate, eventTime, eventType, auth.id).run();

        for (const uid of participantIds) {
          await db.prepare('INSERT INTO event_participants (event_id, user_id) VALUES (?, ?)').bind(id, uid).run();
        }

        await logAudit(db, auth.id, 'CREATE_EVENT', 'events', id, { title, eventDate, eventTime });

        return jsonResponse({ ok: true, event: { id, title, description, eventDate, eventTime, eventType, participants: participantIds } }, 201, request);
      } catch (e) {
        return errorResponse('Error creando evento: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/events/') && method === 'DELETE') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      const evId = path.split('/')[3];
      try {
        await db.prepare('DELETE FROM events WHERE id = ?').bind(evId).run();
        await logAudit(db, auth.id, 'DELETE_EVENT', 'events', evId, {});
        return jsonResponse({ ok: true, id: evId }, 200, request);
      } catch (e) {
        return errorResponse('Error eliminando evento: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // KPI (CALCULADOS DIRECTAMENTE EN SQL EN D1)
    // ===============================================================
    if (path === '/api/kpi' && method === 'GET') {
      const now = new Date();
      const currentMonth = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const todayStr = url.searchParams.get('date') || now.toISOString().split('T')[0];
      const workerParam = url.searchParams.get('worker_id');
      const filterWorker = (!isAdmin) ? auth.id : workerParam;

      // Meta de tienda
      const targetMonthRow = await db.prepare(
        'SELECT target_amount FROM store_targets WHERE period_month = ? AND day IS NULL'
      ).bind(currentMonth).first();
      const totalTarget = targetMonthRow ? targetMonthRow.target_amount : 350000.0;

      // Días del mes y día actual
      const daysInMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
      const currentDay = now.getDate();

      // Ventas acumuladas en el mes
      let monthlySalesSql = 'SELECT COALESCE(SUM(total), 0) as total, COUNT(*) as count FROM sales WHERE sale_date LIKE ?';
      const mParams = [`${currentMonth}%`];
      if (filterWorker) {
        monthlySalesSql += ' AND worker_id = ?';
        mParams.push(filterWorker);
      }
      const monthlySalesRow = await db.prepare(monthlySalesSql).bind(...mParams).first();
      const monthlySales = monthlySalesRow ? monthlySalesRow.total : 0;

      // Ventas de hoy
      let todaySalesSql = 'SELECT COALESCE(SUM(total), 0) as total FROM sales WHERE sale_date = ?';
      const tParams = [todayStr];
      if (filterWorker) {
        todaySalesSql += ' AND worker_id = ?';
        tParams.push(filterWorker);
      }
      const todaySalesRow = await db.prepare(todaySalesSql).bind(...tParams).first();
      const todaySales = todaySalesRow ? todaySalesRow.total : 0;

      // Venta esperada a la fecha y ritmo
      const expectedPace = Math.round((totalTarget / daysInMonth) * currentDay);
      const diffAgainstExpected = monthlySales - expectedPace;
      const projectedClosing = currentDay > 0 ? Math.round((monthlySales / currentDay) * daysInMonth) : 0;
      const targetCompliance = totalTarget > 0 ? ((monthlySales / totalTarget) * 100).toFixed(1) : 0;

      // Ventas por producto
      let productSalesSql = `
        SELECT p.id, p.name, p.category, COALESCE(SUM(s.quantity), 0) as total_qty, COALESCE(SUM(s.total), 0) as total_amount
        FROM products p
        LEFT JOIN sales s ON p.id = s.product_id AND s.sale_date LIKE ? ${filterWorker ? 'AND s.worker_id = ?' : ''}
        WHERE p.active = 1
        GROUP BY p.id
        ORDER BY total_qty DESC
      `;
      const psParams = [`${currentMonth}%`];
      if (filterWorker) psParams.push(filterWorker);
      const { results: productSales } = await db.prepare(productSalesSql).bind(...psParams).all();

      // Ventas por trabajador
      let workerSalesSql = `
        SELECT u.id, u.name, u.role, COALESCE(SUM(s.total), 0) as total_amount, COALESCE(SUM(s.quantity), 0) as total_units
        FROM users u
        LEFT JOIN sales s ON u.id = s.worker_id AND s.sale_date LIKE ?
        WHERE u.active = 1 AND u.role IN ('MOZO', 'ANFITRIONA')
        GROUP BY u.id
        ORDER BY total_amount DESC
      `;
      const { results: workerSales } = await db.prepare(workerSalesSql).bind(`${currentMonth}%`).all();

      return jsonResponse({
        ok: true,
        month: currentMonth,
        currentDay,
        daysInMonth,
        kpis: {
          monthlySales,
          todaySales,
          totalTarget,
          expectedPace,
          diffAgainstExpected,
          projectedClosing,
          targetCompliance: parseFloat(targetCompliance)
        },
        productSales,
        workerSales
      }, 200, request);
    }

    return errorResponse(`Ruta no encontrada: ${method} ${path}`, 404, request);
  }
};
