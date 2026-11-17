/**
 * AdminRest - Cloudflare Worker API REST
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
    // 2. SERVIR ASSETS ESTÁTICOS Y FRONTEND (index.html)
    // ===============================================================
    if (path.toLowerCase().endsWith('/icon.svg') || path.toLowerCase().endsWith('/favicon.ico')) {
      const iconSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="64" height="64" role="img" aria-label="AdminRest">
  <rect x="0" y="0" width="128" height="128" rx="34" fill="#1F5B3D" />
  <rect x="32" y="72" width="15" height="30" rx="4" fill="#FFFFFF" />
  <rect x="56" y="52" width="15" height="50" rx="4" fill="#FFFFFF" />
  <rect x="80" y="30" width="15" height="72" rx="4" fill="#D5A678" />
</svg>`;
      return new Response(iconSvg, {
        status: 200,
        headers: {
          'Content-Type': 'image/svg+xml; charset=utf-8',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }

    if (path.toLowerCase().endsWith('/login.svg')) {
      const loginSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 560 150" width="100%" height="auto" role="img" aria-label="AdminRest - Sistema de gestión Operativa">
  <rect x="16" y="78" width="18" height="40" rx="5" fill="#1F5B3D" />
  <rect x="44" y="52" width="18" height="66" rx="5" fill="#1F5B3D" />
  <rect x="72" y="24" width="18" height="94" rx="5" fill="#D5A678" />
  <text x="110" y="94" font-family="system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="78" font-weight="700" letter-spacing="-2">
    <tspan fill="#1F5B3D">Admin</tspan><tspan fill="#7C5332">Rest</tspan>
  </text>
  <text x="112" y="128" font-family="system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="19" font-weight="500" fill="#6B7280" letter-spacing="0.3">
    Sistema de gestión Operativa
  </text>
</svg>`;
      return new Response(loginSvg, {
        status: 200,
        headers: {
          'Content-Type': 'image/svg+xml; charset=utf-8',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }

    if (path.toLowerCase().endsWith('/nav_logo.svg') || path.toLowerCase().endsWith('/nav-logo.svg')) {
      const navSvg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 560 150" width="100%" height="auto" role="img" aria-label="AdminRest - Sistema de gestión Operativa">
  <rect x="16" y="78" width="18" height="40" rx="5" fill="#FFFFFF" />
  <rect x="44" y="52" width="18" height="66" rx="5" fill="#FFFFFF" />
  <rect x="72" y="24" width="18" height="94" rx="5" fill="#D5A678" />
  <text x="110" y="94" font-family="system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="78" font-weight="700" letter-spacing="-2">
    <tspan fill="#FFFFFF">Admin</tspan><tspan fill="#D5A678">Rest</tspan>
  </text>
  <text x="112" y="128" font-family="system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif" font-size="19" font-weight="500" fill="rgba(255,255,255,0.72)" letter-spacing="0.3">
    Sistema de gestión Operativa
  </text>
</svg>`;
      return new Response(navSvg, {
        status: 200,
        headers: {
          'Content-Type': 'image/svg+xml; charset=utf-8',
          'Cache-Control': 'public, max-age=86400'
        }
      });
    }

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

    if (path.startsWith('/api/products/') && method === 'DELETE') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      const prodId = path.split('/')[3];
      try {
        const current = await db.prepare('SELECT id FROM products WHERE id = ?').bind(prodId).first();
        if (!current) return errorResponse('Producto no encontrado.', 404, request);
        // Soft-delete: mark as inactive instead of hard delete to preserve sales history
        await db.prepare('UPDATE products SET active = 0 WHERE id = ?').bind(prodId).run();
        await logAudit(db, auth.id, 'DELETE_PRODUCT', 'products', prodId, {});
        return jsonResponse({ ok: true, id: prodId }, 200, request);
      } catch (e) {
        return errorResponse('Error eliminando producto: ' + e.message, 500, request);
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
        const workerId = (isAdmin && b.worker_id) ? b.worker_id : auth.id;
        const createdById = auth.id;
        const quantity = parseFloat(b.quantity) || 1;
        const peruDefaultDate = new Date(Date.now() - 5 * 3600000).toISOString().split('T')[0];
        const saleDate = (b.sale_date || peruDefaultDate).trim();
        const notes = (b.notes || '').trim();

        if (!productId) return errorResponse('ID de producto requerido.', 400, request);

        // Precios desacoplados: unit_price y total son puramente informativos
        const unitPrice = b.unit_price !== undefined ? parseFloat(b.unit_price) : 0.0;
        const total = quantity * unitPrice;
        const paymentMethod = (b.payment_method || '').toUpperCase().trim();
        const id = 'sal_' + Date.now() + '_' + Math.random().toString(36).substring(2, 6);

        await db.prepare(
          `INSERT INTO sales (id, sale_date, product_id, worker_id, created_by_id, quantity, unit_price, total, payment_method, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(id, saleDate, productId, workerId, createdById, quantity, unitPrice, total, paymentMethod, notes).run();

        await logAudit(db, auth.id, 'CREATE_SALE', 'sales', id, { workerId, productId, quantity, total, saleDate });

        return jsonResponse({
          ok: true,
          sale: { id, sale_date: saleDate, product_id: productId, worker_id: workerId, created_by_id: createdById, quantity, unit_price: unitPrice, total, payment_method: paymentMethod, notes }
        }, 201, request);
      } catch (e) {
        return errorResponse('Error registrando venta: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // REGISTRO MASIVO DE VENTAS (BULK SALES)
    // ===============================================================
    if (path === '/api/sales/bulk' && method === 'POST') {
      try {
        const b = await request.json();
        const salesList = Array.isArray(b.sales) ? b.sales : [];
        if (salesList.length === 0) {
          return errorResponse('Debe enviar al menos una venta en la lista.', 400, request);
        }

        const peruDefaultDate = new Date(Date.now() - 5 * 3600000).toISOString().split('T')[0];
        const defaultDate = (b.sale_date || peruDefaultDate).trim();
        const defaultWorkerId = (isAdmin && b.worker_id) ? b.worker_id : auth.id;

        const statements = [];
        const createdSales = [];
        const baseTs = Date.now();

        for (let i = 0; i < salesList.length; i++) {
          const item = salesList[i];
          const productId = item.product_id;
          if (!productId) {
            return errorResponse(`Producto ID no válido o inexistente en posición ${i}`, 400, request);
          }

          const workerId = (isAdmin && item.worker_id) ? item.worker_id : defaultWorkerId;
          const createdById = auth.id;
          const quantity = parseFloat(item.quantity) || 1;
          const unitPrice = item.unit_price !== undefined ? parseFloat(item.unit_price) : 0.0;
          const total = quantity * unitPrice;
          const saleDate = (item.sale_date || defaultDate).trim();
          const paymentMethod = (item.payment_method || b.payment_method || '').toUpperCase().trim();
          const notes = (item.notes || b.notes || 'Ingreso masivo').trim();
          const id = `sal_bulk_${baseTs}_${i}_${Math.random().toString(36).substring(2, 5)}`;

          statements.push(
            db.prepare(
              `INSERT INTO sales (id, sale_date, product_id, worker_id, created_by_id, quantity, unit_price, total, payment_method, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            ).bind(id, saleDate, productId, workerId, createdById, quantity, unitPrice, total, paymentMethod, notes)
          );

          createdSales.push({ id, sale_date: saleDate, product_id: productId, worker_id: workerId, quantity, unit_price: unitPrice, total, payment_method: paymentMethod });
        }

        if (statements.length > 0) {
          await db.batch(statements);
          await logAudit(db, auth.id, 'CREATE_SALES_BULK', 'sales', `bulk_${baseTs}`, { count: statements.length, totalUnits: createdSales.reduce((acc, s) => acc + s.quantity, 0) });
        }

        return jsonResponse({
          ok: true,
          count: createdSales.length,
          sales: createdSales
        }, 201, request);
      } catch (e) {
        return errorResponse('Error procesando ventas masivas: ' + e.message, 500, request);
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
    // REGISTROS MENSUALES POR COLABORADOR (Pollos Apoyo y Efectivo)
    // ===============================================================
    if (path === '/api/worker-records' && method === 'GET') {
      const now = new Date();
      const month = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const workerParam = url.searchParams.get('worker_id');
      const filterWorker = (!isAdmin) ? auth.id : workerParam;
      let sql = 'SELECT * FROM worker_monthly_records WHERE period_month = ?';
      const params = [month];
      if (filterWorker) {
        sql += ' AND worker_id = ?';
        params.push(filterWorker);
      }
      const { results } = await db.prepare(sql).bind(...params).all();
      return jsonResponse({ ok: true, records: results || [] }, 200, request);
    }

    if (path === '/api/worker-records' && method === 'POST') {
      try {
        const b = await request.json();
        const now = new Date();
        const month = (b.period_month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`).trim();
        const workerId = (isAdmin && b.worker_id) ? b.worker_id : auth.id;
        const supportPollos = parseFloat(b.support_pollos) || 0.0;
        const cashAchieved = parseFloat(b.cash_achieved) || 0.0;
        const id = `wmr_${month}_${workerId}`;

        await db.prepare(`
          INSERT INTO worker_monthly_records (id, period_month, worker_id, support_pollos, cash_achieved, updated_at)
          VALUES (?, ?, ?, ?, ?, datetime('now'))
          ON CONFLICT(period_month, worker_id) DO UPDATE SET
            support_pollos = excluded.support_pollos,
            cash_achieved = excluded.cash_achieved,
            updated_at = datetime('now')
        `).bind(id, month, workerId, supportPollos, cashAchieved).run();

        await logAudit(db, auth.id, 'SAVE_WORKER_RECORD', 'worker_monthly_records', id, { month, workerId, supportPollos, cashAchieved });
        return jsonResponse({ ok: true, id, period_month: month, worker_id: workerId, support_pollos: supportPollos, cash_achieved: cashAchieved }, 200, request);
      } catch (e) {
        return errorResponse('Error guardando registros del colaborador: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // TIENDA INDEPENDIENTE: MÉTRICAS GLOBALES
    // ===============================================================
    if (path === '/api/store-records' && method === 'GET') {
      const now = new Date();
      const month = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const record = await db.prepare('SELECT * FROM store_monthly_records WHERE period_month = ?').bind(month).first();
      return jsonResponse({
        ok: true,
        record: record || { period_month: month, accumulated_sales: 0.0, monthly_target: 0.0, total_store_pollos: 0.0 }
      }, 200, request);
    }

    if (path === '/api/store-records' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      try {
        const b = await request.json();
        const now = new Date();
        const month = (b.period_month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`).trim();
        const accSales = parseFloat(b.accumulated_sales) || 0.0;
        const mTarget = parseFloat(b.monthly_target) || 0.0;
        const storePollos = parseFloat(b.total_store_pollos) || 0.0;
        const id = `smr_${month}`;

        await db.prepare(`
          INSERT INTO store_monthly_records (id, period_month, accumulated_sales, monthly_target, total_store_pollos, updated_at)
          VALUES (?, ?, ?, ?, ?, datetime('now'))
          ON CONFLICT(period_month) DO UPDATE SET
            accumulated_sales = excluded.accumulated_sales,
            monthly_target = excluded.monthly_target,
            total_store_pollos = excluded.total_store_pollos,
            updated_at = datetime('now')
        `).bind(id, month, accSales, mTarget, storePollos).run();

        await logAudit(db, auth.id, 'SAVE_STORE_RECORD', 'store_monthly_records', id, { month, accSales, mTarget, storePollos });
        return jsonResponse({ ok: true, id, period_month: month, accumulated_sales: accSales, monthly_target: mTarget, total_store_pollos: storePollos }, 200, request);
      } catch (e) {
        return errorResponse('Error guardando métricas de tienda: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // TIENDA INDEPENDIENTE: SEGUIMIENTO POR PRODUCTO
    // ===============================================================
    if (path === '/api/store-products' && method === 'GET') {
      const now = new Date();
      const month = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const { results } = await db.prepare(`
        SELECT p.id as product_id, p.name as product_name, p.category as product_category,
               COALESCE(spr.target_units, 0) as target_units,
               COALESCE(spr.actual_units, 0) as actual_units
        FROM products p
        LEFT JOIN store_product_records spr ON p.id = spr.product_id AND spr.period_month = ?
        WHERE p.active = 1
        ORDER BY p.name ASC
      `).bind(month).all();
      return jsonResponse({ ok: true, products: results || [] }, 200, request);
    }

    if (path === '/api/store-products' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      try {
        const b = await request.json();
        const now = new Date();
        const month = (b.period_month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`).trim();
        const items = Array.isArray(b.records) ? b.records : [b];
        const stmts = [];

        for (const it of items) {
          if (!it.product_id) continue;
          const pid = it.product_id;
          const targetU = parseFloat(it.target_units) || 0.0;
          const actualU = parseFloat(it.actual_units) || 0.0;
          const id = `spr_${month}_${pid}`;
          stmts.push(db.prepare(`
            INSERT INTO store_product_records (id, period_month, product_id, target_units, actual_units, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(period_month, product_id) DO UPDATE SET
              target_units = excluded.target_units,
              actual_units = excluded.actual_units,
              updated_at = datetime('now')
          `).bind(id, month, pid, targetU, actualU));
        }

        if (stmts.length > 0) await db.batch(stmts);
        return jsonResponse({ ok: true, count: stmts.length }, 200, request);
      } catch (e) {
        return errorResponse('Error guardando productos de tienda: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // PESTAÑA PROYECTADO: DÍA POR DÍA
    // ===============================================================
    if (path === '/api/daily-projections' && method === 'GET') {
      const now = new Date();
      const month = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const { results } = await db.prepare(
        'SELECT day, projected_amount, actual_amount FROM daily_projections WHERE period_month = ? ORDER BY day ASC'
      ).bind(month).all();
      return jsonResponse({ ok: true, month, days: results || [] }, 200, request);
    }

    if (path === '/api/daily-projections' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      try {
        const b = await request.json();
        const now = new Date();
        const month = (b.period_month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`).trim();
        const days = Array.isArray(b.days) ? b.days : [b];
        const stmts = [];

        for (const d of days) {
          const dayNum = parseInt(d.day);
          if (!dayNum || dayNum < 1 || dayNum > 31) continue;
          const proj = parseFloat(d.projected_amount) || 0.0;
          const act = parseFloat(d.actual_amount) || 0.0;
          const id = `dp_${month}_${dayNum}`;
          stmts.push(db.prepare(`
            INSERT INTO daily_projections (id, period_month, day, projected_amount, actual_amount, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(period_month, day) DO UPDATE SET
              projected_amount = excluded.projected_amount,
              actual_amount = excluded.actual_amount,
              updated_at = datetime('now')
          `).bind(id, month, dayNum, proj, act));
        }

        if (stmts.length > 0) await db.batch(stmts);
        return jsonResponse({ ok: true, count: stmts.length }, 200, request);
      } catch (e) {
        return errorResponse('Error guardando proyecciones diarias: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // DASHBOARD: OBSERVACIONES Y COMENTARIOS DEL ADMINISTRADOR
    // ===============================================================
    if (path === '/api/worker-comments' && method === 'GET') {
      const workerParam = url.searchParams.get('worker_id');
      const monthParam = url.searchParams.get('month');
      const targetWorker = (!isAdmin) ? auth.id : workerParam;
      let sql = `
        SELECT c.*, u.name as worker_name, a.name as author_name
        FROM worker_comments c
        JOIN users u ON c.worker_id = u.id
        JOIN users a ON c.author_id = a.id
        WHERE 1=1
      `;
      const params = [];
      if (targetWorker) {
        sql += ' AND c.worker_id = ?';
        params.push(targetWorker);
      }
      if (monthParam) {
        sql += ' AND c.period_month = ?';
        params.push(monthParam);
      }
      sql += ' ORDER BY c.created_at DESC';
      const { results } = await db.prepare(sql).bind(...params).all();
      return jsonResponse({ ok: true, comments: results || [] }, 200, request);
    }

    if (path === '/api/worker-comments' && method === 'POST') {
      if (!isAdmin) return errorResponse('Solo el administrador puede registrar comentarios.', 403, request);
      try {
        const b = await request.json();
        const now = new Date();
        const workerId = b.worker_id;
        const month = (b.period_month || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`).trim();
        const commentText = (b.comment || '').trim();

        if (!workerId || !commentText) return errorResponse('Colaborador y comentario son requeridos.', 400, request);

        const id = `wc_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`;
        await db.prepare(`
          INSERT INTO worker_comments (id, worker_id, period_month, author_id, comment, created_at)
          VALUES (?, ?, ?, ?, ?, datetime('now'))
        `).bind(id, workerId, month, auth.id, commentText).run();

        await logAudit(db, auth.id, 'ADD_WORKER_COMMENT', 'worker_comments', id, { workerId, month });
        return jsonResponse({ ok: true, id }, 201, request);
      } catch (e) {
        return errorResponse('Error registrando comentario: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/worker-comments/') && method === 'DELETE') {
      if (!isAdmin) return errorResponse('Solo el administrador puede eliminar comentarios.', 403, request);
      try {
        const commentId = path.split('/')[3];
        await db.prepare('DELETE FROM worker_comments WHERE id = ?').bind(commentId).run();
        return jsonResponse({ ok: true, id: commentId }, 200, request);
      } catch (e) {
        return errorResponse('Error eliminando comentario: ' + e.message, 500, request);
      }
    }

    // ===============================================================
    // METAS (STORE TARGETS, WORKER TARGETS Y PRODUCT GOALS)
    // ===============================================================
    if (path === '/api/goals' && method === 'GET') {
      const now = new Date();
      const currentMonth = url.searchParams.get('month') || `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const workerId = url.searchParams.get('worker_id') || (!isAdmin ? auth.id : null);

      await db.prepare(`
        CREATE TABLE IF NOT EXISTS worker_targets (
          id TEXT PRIMARY KEY,
          period_month TEXT NOT NULL,
          worker_id TEXT NOT NULL REFERENCES users(id),
          target_amount REAL NOT NULL,
          created_at TEXT NOT NULL DEFAULT (datetime('now')),
          UNIQUE(period_month, worker_id)
        )
      `).run();

      const storeTargets = await db.prepare(
        'SELECT * FROM store_targets WHERE period_month = ? ORDER BY day ASC'
      ).bind(currentMonth).all();

      let workerTargetsQuery = `
        SELECT wt.*, u.name as worker_name, u.role as worker_role
        FROM worker_targets wt
        JOIN users u ON wt.worker_id = u.id
        WHERE wt.period_month = ?
      `;
      const wtParams = [currentMonth];
      if (workerId) {
        workerTargetsQuery += ' AND wt.worker_id = ?';
        wtParams.push(workerId);
      }
      const workerTargets = await db.prepare(workerTargetsQuery).bind(...wtParams).all();

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
        storeTargets: storeTargets.results || [],
        productGoals: productGoals.results || [],
        workerTargets: workerTargets.results || []
      }, 200, request);
    }

    if (path === '/api/goals' && method === 'POST') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      try {
        const b = await request.json();
        const type = b.type; // 'STORE_TARGET', 'WORKER_TARGET' o 'PRODUCT_GOAL'
        const periodMonth = b.period_month || `${new Date().getFullYear()}-${String(new Date().getMonth() + 1).padStart(2, '0')}`;

        if (type === 'STORE_TARGET') {
          const day = b.day != null ? parseInt(b.day) : null;
          const targetAmount = parseFloat(b.target_amount) || 0;

          const existing = await db.prepare(
            'SELECT id FROM store_targets WHERE period_month = ? AND (day IS ? OR (day IS NULL AND ? IS NULL))'
          ).bind(periodMonth, day, day).first();

          let finalId;
          if (existing) {
            finalId = existing.id;
            await db.prepare(
              'UPDATE store_targets SET target_amount = ? WHERE id = ?'
            ).bind(targetAmount, finalId).run();
          } else {
            finalId = `st_${periodMonth}_${day != null ? day : 'month'}`;
            await db.prepare(
              'INSERT INTO store_targets (id, period_month, day, target_amount) VALUES (?, ?, ?, ?)'
            ).bind(finalId, periodMonth, day, targetAmount).run();
          }

          await logAudit(db, auth.id, 'SET_STORE_TARGET', 'store_targets', finalId, { periodMonth, day, targetAmount });
          return jsonResponse({ ok: true, id: finalId, periodMonth, day, targetAmount }, 200, request);

        } else if (type === 'WORKER_TARGET') {
          const workerId = b.worker_id;
          const targetAmount = parseFloat(b.target_amount) || 0;
          const cashTargetAmount = b.cash_target_amount !== undefined ? parseFloat(b.cash_target_amount) : 0;
          if (!workerId) return errorResponse('worker_id es requerido.', 400, request);

          await db.prepare(`
            CREATE TABLE IF NOT EXISTS worker_targets (
              id TEXT PRIMARY KEY,
              period_month TEXT NOT NULL,
              worker_id TEXT NOT NULL REFERENCES users(id),
              target_amount REAL NOT NULL,
              cash_target_amount REAL DEFAULT 0.0,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              UNIQUE(period_month, worker_id)
            )
          `).run();

          const existing = await db.prepare(
            'SELECT id FROM worker_targets WHERE period_month = ? AND worker_id = ?'
          ).bind(periodMonth, workerId).first();

          let finalId;
          if (existing) {
            finalId = existing.id;
            await db.prepare(
              'UPDATE worker_targets SET target_amount = ?, cash_target_amount = ? WHERE id = ?'
            ).bind(targetAmount, cashTargetAmount, finalId).run();
          } else {
            finalId = `wt_${periodMonth}_${workerId}`;
            await db.prepare(
              'INSERT INTO worker_targets (id, period_month, worker_id, target_amount, cash_target_amount) VALUES (?, ?, ?, ?, ?)'
            ).bind(finalId, periodMonth, workerId, targetAmount, cashTargetAmount).run();
          }

          await logAudit(db, auth.id, 'SET_WORKER_TARGET', 'worker_targets', finalId, { periodMonth, workerId, targetAmount, cashTargetAmount });
          return jsonResponse({ ok: true, id: finalId, periodMonth, workerId, targetAmount, cashTargetAmount }, 200, request);

        } else if (type === 'PRODUCT_GOAL') {
          const productId = b.product_id;
          const workerId = b.worker_id || null;
          const targetQuantity = parseFloat(b.target_quantity) || 0;

          if (!productId) return errorResponse('product_id es requerido.', 400, request);

          const existingGoal = workerId
            ? await db.prepare(
                'SELECT id FROM product_goals WHERE period_month = ? AND product_id = ? AND worker_id = ?'
              ).bind(periodMonth, productId, workerId).first()
            : await db.prepare(
                'SELECT id FROM product_goals WHERE period_month = ? AND product_id = ? AND worker_id IS NULL'
              ).bind(periodMonth, productId).first();

          let finalGoalId;
          if (existingGoal) {
            finalGoalId = existingGoal.id;
            await db.prepare(
              'UPDATE product_goals SET target_quantity = ? WHERE id = ?'
            ).bind(targetQuantity, finalGoalId).run();
          } else {
            finalGoalId = `pg_${periodMonth}_${productId}_${workerId || 'store'}`;
            await db.prepare(
              'INSERT INTO product_goals (id, period_month, product_id, worker_id, target_quantity) VALUES (?, ?, ?, ?, ?)'
            ).bind(finalGoalId, periodMonth, productId, workerId, targetQuantity).run();
          }

          await logAudit(db, auth.id, 'SET_PRODUCT_GOAL', 'product_goals', finalGoalId, { periodMonth, productId, workerId, targetQuantity });
          return jsonResponse({ ok: true, id: finalGoalId, periodMonth, productId, workerId, targetQuantity }, 200, request);

        } else {
          return errorResponse('Tipo de meta desconocido.', 400, request);
        }
      } catch (e) {
        return errorResponse('Error guardando meta: ' + e.message, 500, request);
      }
    }

    if (path.startsWith('/api/goals/') && method === 'DELETE') {
      if (!isAdmin) return errorResponse('Permiso denegado. Solo administrador.', 403, request);
      const goalId = path.split('/')[3];
      try {
        await db.prepare(`
          CREATE TABLE IF NOT EXISTS worker_targets (
            id TEXT PRIMARY KEY,
            period_month TEXT NOT NULL,
            worker_id TEXT NOT NULL REFERENCES users(id),
            target_amount REAL NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(period_month, worker_id)
          )
        `).run();

        let res = await db.prepare('DELETE FROM worker_targets WHERE id = ?').bind(goalId).run();
        if (!res.meta || res.meta.changes === 0) {
          res = await db.prepare('DELETE FROM product_goals WHERE id = ?').bind(goalId).run();
        }
        if (!res.meta || res.meta.changes === 0) {
          res = await db.prepare('DELETE FROM store_targets WHERE id = ?').bind(goalId).run();
        }
        await logAudit(db, auth.id, 'DELETE_GOAL', 'goals', goalId, {});
        return jsonResponse({ ok: true, id: goalId }, 200, request);
      } catch (e) {
        return errorResponse('Error eliminando meta: ' + e.message, 500, request);
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

    if (path.startsWith('/api/tasks/') && method === 'DELETE') {
      if (!isAdmin) return errorResponse('Permiso denegado.', 403, request);
      const taskId = path.split('/')[3];
      try {
        const current = await db.prepare('SELECT id FROM tasks WHERE id = ?').bind(taskId).first();
        if (!current) return errorResponse('Tarea no encontrada.', 404, request);
        // task_assignees rows are deleted via ON DELETE CASCADE
        await db.prepare('DELETE FROM tasks WHERE id = ?').bind(taskId).run();
        await logAudit(db, auth.id, 'DELETE_TASK', 'tasks', taskId, {});
        return jsonResponse({ ok: true, id: taskId }, 200, request);
      } catch (e) {
        return errorResponse('Error eliminando tarea: ' + e.message, 500, request);
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
      const productIdParam = url.searchParams.get('product_id');
      const filterWorker = (!isAdmin) ? auth.id : workerParam;

      // Métricas de tienda independientes
      const storeRec = await db.prepare(
        'SELECT * FROM store_monthly_records WHERE period_month = ?'
      ).bind(currentMonth).first();

      const legacyTargetRow = await db.prepare(
        'SELECT target_amount FROM store_targets WHERE period_month = ? AND day IS NULL'
      ).bind(currentMonth).first();

      const totalTarget = (storeRec && storeRec.monthly_target > 0)
        ? storeRec.monthly_target
        : (legacyTargetRow ? legacyTargetRow.target_amount : 350000.0);

      const storeAccumulatedSales = storeRec ? storeRec.accumulated_sales : 0.0;
      const storeTotalPollos = storeRec ? storeRec.total_store_pollos : 0.0;

      // Suma independiente de metas de efectivo asignadas a colaboradores
      const workerTargetsSumRow = await db.prepare(
        'SELECT COALESCE(SUM(target_amount), 0) as total, COALESCE(SUM(cash_target_amount), 0) as cash_total FROM worker_targets WHERE period_month = ?'
      ).bind(currentMonth).first();
      const workerTargetsSum = workerTargetsSumRow ? workerTargetsSumRow.total : 0;
      const workerCashTargetsSum = workerTargetsSumRow ? workerTargetsSumRow.cash_total : 0;

      // Días del mes y día actual
      const [yStr, mStr] = currentMonth.split('-');
      const y = parseInt(yStr) || now.getFullYear();
      const m = parseInt(mStr) || (now.getMonth() + 1);
      const daysInMonth = new Date(y, m, 0).getDate();
      const isCurrentMonth = currentMonth === `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
      const currentDay = isCurrentMonth ? now.getDate() : daysInMonth;

      // Ventas de productos en unidades en el mes
      let monthlySalesSql = 'SELECT COALESCE(SUM(quantity), 0) as total_units, COUNT(*) as count FROM sales WHERE sale_date LIKE ?';
      const mParams = [`${currentMonth}%`];
      if (filterWorker) {
        monthlySalesSql += ' AND worker_id = ?';
        mParams.push(filterWorker);
      }
      if (productIdParam) {
        monthlySalesSql += ' AND product_id = ?';
        mParams.push(productIdParam);
      }
      const monthlySalesRow = await db.prepare(monthlySalesSql).bind(...mParams).first();
      const monthlyProductUnits = monthlySalesRow ? monthlySalesRow.total_units : 0;

      // Proyecciones diarias (de tabla daily_projections con fallback a store_targets)
      const dailyProjRows = await db.prepare(
        'SELECT day, projected_amount, actual_amount FROM daily_projections WHERE period_month = ? ORDER BY day ASC'
      ).bind(currentMonth).all();
      const dailyProjMap = new Map();
      (dailyProjRows.results || []).forEach(r => dailyProjMap.set(r.day, { projected: r.projected_amount, actual: r.actual_amount }));

      const legacyDailyTargets = await db.prepare(
        'SELECT day, target_amount FROM store_targets WHERE period_month = ? AND day IS NOT NULL'
      ).bind(currentMonth).all();
      const legacyDailyMap = new Map();
      (legacyDailyTargets.results || []).forEach(r => legacyDailyMap.set(r.day, r.target_amount));

      const defaultDailyTarget = daysInMonth > 0 ? Math.round(totalTarget / daysInMonth) : 0;
      const dailyList = [];
      let totalActualProjectedMonth = 0;
      let totalProjectedMonth = 0;

      for (let d = 1; d <= daysInMonth; d++) {
        const dStr = String(d).padStart(2, '0');
        let target = defaultDailyTarget;
        let actual = 0;

        if (dailyProjMap.has(d)) {
          const dp = dailyProjMap.get(d);
          target = dp.projected;
          actual = dp.actual;
        } else if (legacyDailyMap.has(d)) {
          target = legacyDailyMap.get(d);
        }

        const diff = actual - target;
        totalActualProjectedMonth += actual;
        totalProjectedMonth += target;

        dailyList.push({
          day: d,
          date: `${currentMonth}-${dStr}`,
          target,
          actual,
          diff
        });
      }

      // Venta esperada a la fecha y ritmo sobre meta de tienda
      const expectedPace = Math.round((totalTarget / daysInMonth) * currentDay);
      const diffAgainstExpected = storeAccumulatedSales - expectedPace;
      const projectedClosing = currentDay > 0 ? Math.round((storeAccumulatedSales / currentDay) * daysInMonth) : 0;
      const targetCompliance = totalTarget > 0 ? ((storeAccumulatedSales / totalTarget) * 100).toFixed(1) : 0;

      // Productos de tienda independientes
      const { results: storeProductStats } = await db.prepare(`
        SELECT p.id, p.name, p.category,
               COALESCE(spr.target_units, 0) as target_units,
               COALESCE(spr.actual_units, 0) as actual_units
        FROM products p
        LEFT JOIN store_product_records spr ON p.id = spr.product_id AND spr.period_month = ?
        WHERE p.active = 1
        ORDER BY p.name ASC
      `).bind(currentMonth).all();

      // Ventas por producto de colaboradores (unidades)
      let productSalesSql = `
        SELECT p.id, p.name, p.category,
               COALESCE(SUM(s.quantity), 0) as total_qty
        FROM products p
        LEFT JOIN sales s ON p.id = s.product_id AND s.sale_date LIKE ? ${filterWorker ? 'AND s.worker_id = ?' : ''}
        WHERE p.active = 1
        GROUP BY p.id
        ORDER BY total_qty DESC
      `;
      const psParams = [`${currentMonth}%`];
      if (filterWorker) psParams.push(filterWorker);
      const { results: productSales } = await db.prepare(productSalesSql).bind(...psParams).all();

      // Colaboradores con sus metas de efectivo y sus logros manuales
      let workerSalesSql = `
        SELECT u.id, u.name, u.role,
               COALESCE(wt.cash_target_amount, wt.target_amount, 0) as cash_target,
               COALESCE(wmr.cash_achieved, 0) as cash_amount,
               COALESCE(wmr.support_pollos, 0) as support_pollos,
               COALESCE(SUM(s.quantity), 0) as total_units
        FROM users u
        LEFT JOIN worker_targets wt ON u.id = wt.worker_id AND wt.period_month = ?
        LEFT JOIN worker_monthly_records wmr ON u.id = wmr.worker_id AND wmr.period_month = ?
        LEFT JOIN sales s ON u.id = s.worker_id AND s.sale_date LIKE ? ${productIdParam ? 'AND s.product_id = ?' : ''}
        WHERE u.active = 1 AND u.role IN ('MOZO', 'ANFITRIONA')
        GROUP BY u.id
        ORDER BY total_units DESC, cash_amount DESC
      `;
      const wsParams = [currentMonth, currentMonth, `${currentMonth}%`];
      if (productIdParam) wsParams.push(productIdParam);
      const { results: workerSales } = await db.prepare(workerSalesSql).bind(...wsParams).all();

      return jsonResponse({
        ok: true,
        month: currentMonth,
        currentDay,
        daysInMonth,
        filterProductId: productIdParam || null,
        kpis: {
          monthlySales: storeAccumulatedSales,
          monthlyProductUnits,
          cashSales: storeAccumulatedSales,
          totalTarget,
          storeTotalPollos,
          totalActualProjectedMonth,
          totalProjectedMonth,
          workerTargetsSum,
          workerCashTargetsSum,
          expectedPace,
          diffAgainstExpected,
          projectedClosing,
          targetCompliance: parseFloat(targetCompliance)
        },
        dailyList,
        productSales,
        storeProductStats: storeProductStats || [],
        workerSales
      }, 200, request);
    }

    return errorResponse(`Ruta no encontrada: ${method} ${path}`, 404, request);
  }
};
