import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { v4 as uuid } from 'uuid';
import jwt from 'jsonwebtoken';
import fetch from 'node-fetch';

const app = express();
const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

app.use((req, res, next) => {
  req.id = req.headers['x-request-id'] || uuid();
  res.setHeader('x-request-id', req.id);
  next();
});

app.use(pinoHttp({ logger, genReqId: req => req.id }));
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
// auth + entitlements middleware (stub)
app.use(async (req, res, next) => {
  const openPaths = ['/healthz', '/readyz', '/auth/login'];
  if (openPaths.includes(req.path)) return next();
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Missing token', requestId: req.id });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    req.user = decoded;
    // fetch entitlements (tenantId inferred from org/business scope)
    const tenantId = decoded.scopes?.orgId || decoded.scopes?.businesses?.[0] || 'default';
    try {
      const url = process.env.ENTITLEMENTS_URL || 'http://localhost:7002/entitlements/' + tenantId;
      const resp = await fetch(url);
      req.entitlements = resp.ok ? await resp.json() : { modules: {}, features: {} };
    } catch {
      req.entitlements = { modules: {}, features: {} };
    }
    return next();
  } catch (e) {
    return res.status(401).json({ message: 'Invalid token', requestId: req.id });
  }
});

// basic rate limit (token bucket) – lightweight starter
let TOKENS = Number(process.env.RATE_TOKENS || 200);
const INTERVAL = Number(process.env.RATE_REFILL_MS || 1000);
setInterval(() => (TOKENS = Number(process.env.RATE_TOKENS || 200)), INTERVAL);
app.use((req, res, next) => {
  if (TOKENS <= 0) return res.status(429).json({ message: 'Too many requests', requestId: req.id });
  TOKENS -= 1;
  next();
});

app.get('/healthz', (req, res) => res.json({ status: 'ok', requestId: req.id }));
app.get('/readyz', (req, res) => res.json({ status: 'ready' }));
// aggregated readiness
app.get('/readyz/full', async (req, res) => {
  try {
    const ORG_BASE = process.env.ORG_SERVICE_URL || 'http://localhost:7003';
    const FORMS_BASE = process.env.FORMS_SERVICE_URL || 'http://localhost:7004';
    const SUBMISSIONS_BASE = process.env.SUBMISSIONS_SERVICE_URL || 'http://localhost:3005';
    const DISCOUNTS_BASE = process.env.DISCOUNTS_SERVICE_URL || 'http://localhost:3006';
    const STAFF_BASE = process.env.STAFF_SERVICE_URL || 'http://localhost:3007';
    const services = {
      org: `${ORG_BASE}/ready`,
      forms: `${FORMS_BASE}/ready`,
      submissions: `${SUBMISSIONS_BASE}/ready`,
      discounts: `${DISCOUNTS_BASE}/ready`,
      staff: `${STAFF_BASE}/ready`,
    };
    const entries = await Promise.all(
      Object.entries(services).map(async ([k, url]) => {
        try {
          const r = await fetch(url);
          return [k, r.ok];
        } catch {
          return [k, false];
        }
      })
    );
    const status = Object.fromEntries(entries);
    const allOk = Object.values(status).every(Boolean);
    res.status(allOk ? 200 : 503).json({ ready: allOk, status });
  } catch (e) {
    res.status(503).json({ ready: false });
  }
});

// placeholder routes (will proxy to services later)
app.get('/api/v1/me', (req, res) => res.json({ user: req.user || null, entitlements: req.entitlements || null, requestId: req.id }));

const port = Number(process.env.PORT || 8080);
app.listen(port, () => logger.info({ port }, 'gateway-bff listening'));

// ---- ORG-SERVICE PROXY ROUTES ----
const ORG_BASE = process.env.ORG_SERVICE_URL || 'http://localhost:7003';
const FORMS_BASE = process.env.FORMS_SERVICE_URL || 'http://localhost:7004';
const SUBMISSIONS_BASE = process.env.SUBMISSIONS_SERVICE_URL || 'http://localhost:3005';
const DISCOUNTS_BASE = process.env.DISCOUNTS_SERVICE_URL || 'http://localhost:3006';
const STAFF_BASE = process.env.STAFF_SERVICE_URL || 'http://localhost:3007';
const NOTIFY_BASE = process.env.NOTIFICATIONS_SERVICE_URL || 'http://localhost:3008';
const REPORT_BASE = process.env.REPORTING_SERVICE_URL || 'http://localhost:3009';
const I18N_BASE = process.env.TRANSLATION_SERVICE_URL || 'http://localhost:3010';
const FLAGS_BASE = process.env.FEATURE_FLAGS_SERVICE_URL || 'http://localhost:3011';
const API_PROG_BASE = process.env.API_PROGRAM_SERVICE_URL || 'http://localhost:3012';
const SEARCH_BASE = process.env.SEARCH_SERVICE_URL || 'http://localhost:3013';
const METER_BASE = process.env.METERING_SERVICE_URL || 'http://localhost:3014';
const INTEG_BASE = process.env.INTEGRATION_HUB_SERVICE_URL || 'http://localhost:3015';
const EXPORT_BASE = process.env.EXPORT_SCHED_SERVICE_URL || 'http://localhost:3016';

app.get('/api/org/:id', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/org/${req.params.id}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

// ---- FORMS-SERVICE PROXY ROUTES ----
app.post('/api/forms', async (req, res) => {
  try {
    const r = await fetch(`${FORMS_BASE}/forms`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'forms-service unavailable', requestId: req.id }); }
});

app.get('/api/forms/:id', async (req, res) => {
  try {
    const r = await fetch(`${FORMS_BASE}/forms/${req.params.id}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'forms-service unavailable', requestId: req.id }); }
});

app.patch('/api/forms/:id', async (req, res) => {
  try {
    const r = await fetch(`${FORMS_BASE}/forms/${req.params.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'forms-service unavailable', requestId: req.id }); }
});

app.delete('/api/forms/:id', async (req, res) => {
  try {
    const r = await fetch(`${FORMS_BASE}/forms/${req.params.id}`, { method: 'DELETE' });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'forms-service unavailable', requestId: req.id }); }
});

app.get('/api/forms/by-code/:code', async (req, res) => {
  try {
    const r = await fetch(`${FORMS_BASE}/forms/by-code/${req.params.code}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'forms-service unavailable', requestId: req.id }); }
});

app.post('/api/franchise/:id/forms', async (req, res) => {
  try {
    const r = await fetch(`${FORMS_BASE}/franchise/${req.params.id}/forms`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'forms-service unavailable', requestId: req.id }); }
});

app.post('/api/org', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/org`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.get('/api/brand', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${ORG_BASE}/brand?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.post('/api/brand', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/brand`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.get('/api/business', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${ORG_BASE}/business?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.post('/api/business', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/business`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.get('/api/business/:id', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/business/${req.params.id}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.patch('/api/business/:id', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/business/${req.params.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.get('/api/franchise', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${ORG_BASE}/franchise?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.post('/api/franchise', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/franchise`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.get('/api/franchise/:id', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/franchise/${req.params.id}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

app.patch('/api/franchise/:id', async (req, res) => {
  try {
    const r = await fetch(`${ORG_BASE}/franchise/${req.params.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'org-service unavailable', requestId: req.id });
  }
});

// ---- SUBMISSIONS-SERVICE PROXY ROUTES ----
app.post('/api/submissions', async (req, res) => {
  try {
    const r = await fetch(`${SUBMISSIONS_BASE}/submissions`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-user-id': req.user?.id || '' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'submissions-service unavailable', requestId: req.id });
  }
});

app.get('/api/submissions/by-business/:businessId', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${SUBMISSIONS_BASE}/submissions/by-business/${req.params.businessId}?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'submissions-service unavailable', requestId: req.id });
  }
});

// ---- DISCOUNTS-SERVICE PROXY ROUTES ----
app.get('/api/discounts/:accessKey', async (req, res) => {
  try {
    const r = await fetch(`${DISCOUNTS_BASE}/discounts/${req.params.accessKey}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'discounts-service unavailable', requestId: req.id });
  }
});

app.post('/api/discounts/mark-used', async (req, res) => {
  try {
    const r = await fetch(`${DISCOUNTS_BASE}/discounts/mark-used`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'discounts-service unavailable', requestId: req.id });
  }
});

// ---- STAFF-SERVICE PROXY ROUTES ----
app.post('/api/staff', async (req, res) => {
  try {
    const r = await fetch(`${STAFF_BASE}/staff`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'staff-service unavailable', requestId: req.id });
  }
});

app.get('/api/staff', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${STAFF_BASE}/staff?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'staff-service unavailable', requestId: req.id });
  }
});

app.patch('/api/staff/:id', async (req, res) => {
  try {
    const r = await fetch(`${STAFF_BASE}/staff/${req.params.id}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'staff-service unavailable', requestId: req.id });
  }
});

app.delete('/api/staff/:id', async (req, res) => {
  try {
    const r = await fetch(`${STAFF_BASE}/staff/${req.params.id}`, { method: 'DELETE' });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'staff-service unavailable', requestId: req.id });
  }
});

app.post('/api/staff/:id/schedule', async (req, res) => {
  try {
    const r = await fetch(`${STAFF_BASE}/staff/${req.params.id}/schedule`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(req.body) });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'staff-service unavailable', requestId: req.id });
  }
});

app.get('/api/staff/:id/schedule', async (req, res) => {
  try {
    const r = await fetch(`${STAFF_BASE}/staff/${req.params.id}/schedule`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'staff-service unavailable', requestId: req.id });
  }
});

// ---- NOTIFICATIONS-SERVICE PROXY ROUTES ----
app.get('/api/notifications/rules', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${NOTIFY_BASE}/rules?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'notifications-service unavailable', requestId: req.id });
  }
});

// ---- REPORTING-SERVICE PROXY ROUTES ----
app.get('/api/reports/live/:businessId', async (req, res) => {
  try {
    const r = await fetch(`${REPORT_BASE}/reports/live/${req.params.businessId}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'reporting-service unavailable', requestId: req.id });
  }
});

// Entitlements guard (stub) + feature flag guard
const featureEnabled = (flag) => (req, res, next) => {
  const flags = (req.entitlements && req.entitlements.features) || {};
  if (flags[flag] === false) return res.status(403).json({ message: `Feature disabled: ${flag}` });
  return next();
};
const moduleEnabled = (moduleKey) => (req, res, next) => {
  const mods = (req.entitlements && req.entitlements.modules) || {};
  if (mods[moduleKey] === false) return res.status(403).json({ message: `Module disabled: ${moduleKey}` });
  return next();
};

// apply guards to route groups
app.use('/api/forms', moduleEnabled('forms'));
app.use('/api/submissions', moduleEnabled('submissions'));
app.use('/api/discounts', moduleEnabled('discounts'));
app.use('/api/staff', moduleEnabled('staff'));
app.use('/api/reports', featureEnabled('reports'));
app.use('/api/i18n', featureEnabled('i18n'));
app.use('/api/webhooks', featureEnabled('integrationHub'));
app.use('/api/schedules', featureEnabled('exportScheduler'));

// ---- TRANSLATION-SERVICE PROXY ----
app.get('/api/i18n/:namespace', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${I18N_BASE}/i18n/${req.params.namespace}?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'translation-service unavailable', requestId: req.id });
  }
});

// ---- FEATURE-FLAGS SERVICE PROXY ----
app.get('/api/flags/:tenantId', async (req, res) => {
  try {
    const r = await fetch(`${FLAGS_BASE}/flags/${req.params.tenantId}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) {
    res.status(502).json({ message: 'feature-flags-service unavailable', requestId: req.id });
  }
});

// ---- API PROGRAM PROXY ----
app.get('/api/api-keys/:tenantId', async (req, res) => {
  try {
    const r = await fetch(`${API_PROG_BASE}/api-keys/${req.params.tenantId}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'api-program-service unavailable', requestId: req.id }); }
});

// ---- SEARCH PROXY ----
app.get('/api/search', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${SEARCH_BASE}/search?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'search-service unavailable', requestId: req.id }); }
});

// ---- METERING PROXY ----
app.get('/api/usage/:tenantId', async (req, res) => {
  try {
    const r = await fetch(`${METER_BASE}/usage/${req.params.tenantId}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'metering-service unavailable', requestId: req.id }); }
});

// Metering: count write requests (simple example)
const meterWrite = async (tenantId, metric) => {
  try {
    await fetch(`${METER_BASE}/usage/increment`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ tenantId, metric, value: 1 }) });
  } catch {}
};

// wrap selected write routes to increment metrics
const wrapWrite = (handler, metric) => async (req, res) => {
  const tenantId = req.user?.scopes?.orgId || req.user?.scopes?.businesses?.[0] || 'default';
  await handler(req, res);
  if (res.statusCode < 500) meterWrite(tenantId, metric);
};

// ---- INTEGRATION HUB PROXY ----
app.get('/api/webhooks', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${INTEG_BASE}/webhooks?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'integration-hub-service unavailable', requestId: req.id }); }
});

// ---- EXPORT SCHEDULER PROXY ----
app.get('/api/schedules', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${EXPORT_BASE}/schedules?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'export-scheduler-service unavailable', requestId: req.id }); }
});

// ---- AI/ML SERVICE PROXY ----
const AI_ML_BASE = process.env.AI_ML_SERVICE_URL || 'http://localhost:3017';
app.post('/api/ai-ml/analyze/sentiment', async (req, res) => {
  try {
    const r = await fetch(`${AI_ML_BASE}/analyze/sentiment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'ai-ml-service unavailable', requestId: req.id }); }
});

app.post('/api/ai-ml/analyze/topics', async (req, res) => {
  try {
    const r = await fetch(`${AI_ML_BASE}/analyze/topics`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'ai-ml-service unavailable', requestId: req.id }); }
});

app.get('/api/ai-ml/insights/:tenantId', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${AI_ML_BASE}/insights/${req.params.tenantId}?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'ai-ml-service unavailable', requestId: req.id }); }
});

// ---- AUDIT SERVICE PROXY ----
const AUDIT_BASE = process.env.AUDIT_SERVICE_URL || 'http://localhost:3018';
app.post('/api/audit/log', async (req, res) => {
  try {
    const r = await fetch(`${AUDIT_BASE}/audit/log`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'audit-service unavailable', requestId: req.id }); }
});

app.get('/api/audit/:tenantId', async (req, res) => {
  try {
    const qs = new URLSearchParams(req.query).toString();
    const r = await fetch(`${AUDIT_BASE}/audit/${req.params.tenantId}?${qs}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'audit-service unavailable', requestId: req.id }); }
});

// ---- TENANT ISOLATION SERVICE PROXY ----
const TENANT_ISOLATION_BASE = process.env.TENANT_ISOLATION_SERVICE_URL || 'http://localhost:3019';
app.get('/api/tenants/:tenantId', async (req, res) => {
  try {
    const r = await fetch(`${TENANT_ISOLATION_BASE}/tenants/${req.params.tenantId}`);
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'tenant-isolation-service unavailable', requestId: req.id }); }
});

app.post('/api/tenant-isolation/validate-access', async (req, res) => {
  try {
    const r = await fetch(`${TENANT_ISOLATION_BASE}/validate-access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
    });
    const j = await r.json();
    res.status(r.status).json(j);
  } catch (e) { res.status(502).json({ message: 'tenant-isolation-service unavailable', requestId: req.id }); }
});


