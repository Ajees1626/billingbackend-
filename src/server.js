import 'dotenv/config'
import bcrypt from 'bcryptjs'
import cors from 'cors'
import express from 'express'
import jwt from 'jsonwebtoken'
import {
  deleteAllClients,
  deleteClientById,
  findClientById,
  insertClient,
  listClients,
  replaceClient,
} from './clientsStore.js'
import { connectDb, getDb } from './db.js'
import { findStaffById, findStaffByUsername, insertStaff } from './staffStore.js'
import {
  findUserById,
  findUserByUsername,
  findUserByUsernameAndEmail,
  insertUser,
  normalizeEmail,
  publicUser,
  replaceUserById,
} from './userStore.js'

const PORT = Number(process.env.PORT) || 4000
const JWT_SECRET = process.env.JWT_SECRET || 'pixdot-dev-secret-change-me'
const JWT_EXPIRES_DAYS = Math.max(1, Number(process.env.JWT_EXPIRES_DAYS) || 30)

const RESERVED_REGISTER = new Set(['admin', 'staff', 'root', 'system', 'pixdot', 'support'])

const ADMIN_ID = 'u_admin_root'
const ADMIN_USERNAME = 'admin'
const ADMIN_EMAIL = 'admin@pixdot.local'
const ADMIN_PASSWORD = '123456'

function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }
}

function signToken(userDoc) {
  return jwt.sign({ sub: userDoc.id, email: userDoc.email }, JWT_SECRET, {
    expiresIn: `${JWT_EXPIRES_DAYS}d`,
  })
}

const authMiddleware = asyncHandler(async (req, res, next) => {
  const h = req.headers.authorization
  const token = h?.startsWith('Bearer ') ? h.slice(7) : null
  if (!token) {
    res.status(401).json({ error: 'Missing token' })
    return
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    let raw = await findUserById(payload.sub)
    if (!raw) raw = await findStaffById(payload.sub)
    if (!raw) {
      res.status(401).json({ error: 'User not found' })
      return
    }
    req.user = raw
    next()
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' })
  }
})

async function ensurePermanentAdmin() {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 10)
  const doc = {
    id: ADMIN_ID,
    username: ADMIN_USERNAME,
    usernameLower: ADMIN_USERNAME,
    email: ADMIN_EMAIL,
    passwordHash: hash,
    role: 'admin',
    createdAt: new Date().toISOString(),
  }
  await replaceUserById(ADMIN_ID, doc)
  console.log(`[pixdot] Admin login: username "${ADMIN_USERNAME}" / password "${ADMIN_PASSWORD}" / email ${ADMIN_EMAIL}`)
}

const app = express()
app.use(
  cors({
    origin: true,
    credentials: true,
  }),
)
app.use(express.json({ limit: '2mb' }))

app.get(
  '/api/health',
  asyncHandler(async (_req, res) => {
    await getDb().command({ ping: 1 })
    res.json({ ok: true, db: 'mongodb' })
  }),
)

/** Self-signup: new clients only (no staff/admin). Opens onboarding until linked to a client record. */
app.post(
  '/api/auth/register',
  asyncHandler(async (req, res) => {
    const username = String(req.body?.username || '').trim()
    const email = normalizeEmail(req.body?.email)
    const password = String(req.body?.password || '')

    if (username.length < 2) {
      res.status(400).json({ error: 'Username must be at least 2 characters' })
      return
    }
    if (RESERVED_REGISTER.has(username.toLowerCase())) {
      res.status(400).json({ error: 'That username is reserved' })
      return
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).json({ error: 'Valid email is required' })
      return
    }
    if (password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters' })
      return
    }

    if (await findUserByUsernameAndEmail(username, email)) {
      res.status(409).json({ error: 'Account already exists with this username and email' })
      return
    }
    if (await findUserByUsername(username)) {
      res.status(409).json({ error: 'Username already taken' })
      return
    }
    if (await findStaffByUsername(username)) {
      res.status(409).json({ error: 'Username already taken' })
      return
    }
    const emailRow = await getDb().collection('users').findOne({ email })
    if (emailRow) {
      res.status(409).json({ error: 'Email already registered' })
      return
    }

    const id = `u_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`
    const user = {
      id,
      username,
      usernameLower: username.toLowerCase(),
      email,
      passwordHash: bcrypt.hashSync(password, 10),
      role: 'client',
      createdAt: new Date().toISOString(),
    }
    await insertUser(user)

    const token = signToken(user)
    res.status(201).json({ token, user: publicUser(user) })
  }),
)

/**
 * Login:
 * - Username + password only: admin, staff (`staff` collection or legacy `users` staff), portal clients (`users` with clientId).
 * - Username + email + password: self-registered clients (no clientId) and optional full sign-in for anyone; staff may use assigned email.
 */
app.post(
  '/api/auth/login',
  asyncHandler(async (req, res) => {
    const username = String(req.body?.username || '').trim()
    const emailRaw = String(req.body?.email ?? '').trim()
    const email = normalizeEmail(emailRaw)
    const password = String(req.body?.password || '')

    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' })
      return
    }

    const hasFullEmail =
      Boolean(emailRaw) &&
      Boolean(email) &&
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)

    if (hasFullEmail) {
      const user = await findUserByUsernameAndEmail(username, email)
      if (user?.passwordHash && bcrypt.compareSync(password, user.passwordHash)) {
        const token = signToken(user)
        res.json({ token, user: publicUser(user) })
        return
      }

      const staffWithEmail = await findStaffByUsername(username)
      if (
        staffWithEmail?.passwordHash &&
        normalizeEmail(staffWithEmail.email) === email &&
        bcrypt.compareSync(password, staffWithEmail.passwordHash)
      ) {
        const token = signToken(staffWithEmail)
        res.json({ token, user: publicUser(staffWithEmail) })
        return
      }

      res.status(401).json({ error: 'Invalid username, email, or password' })
      return
    }

    const staff = await findStaffByUsername(username)
    if (staff?.passwordHash && bcrypt.compareSync(password, staff.passwordHash)) {
      const token = signToken(staff)
      res.json({ token, user: publicUser(staff) })
      return
    }

    const userByName = await findUserByUsername(username)
    if (!userByName?.passwordHash || !bcrypt.compareSync(password, userByName.passwordHash)) {
      res.status(401).json({ error: 'Invalid username or password' })
      return
    }

    const r = userByName.role
    if (r === 'admin' || r === 'staff') {
      const token = signToken(userByName)
      res.json({ token, user: publicUser(userByName) })
      return
    }
    if (r === 'client' && userByName.clientId) {
      const token = signToken(userByName)
      res.json({ token, user: publicUser(userByName) })
      return
    }

    res.status(401).json({
      error:
        'Use your registered email as well — new client accounts need username, email, and password.',
    })
  }),
)

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: publicUser(req.user) })
})

/** Admin only: create staff → saved in `staff` collection. Staff sign in with username + password (email optional on login). */
app.post(
  '/api/auth/staff',
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (publicUser(req.user).role !== 'admin') {
      res.status(403).json({ error: 'Only admins can create staff accounts' })
      return
    }
    const u = String(req.body?.username || '').trim()
    const pw = String(req.body?.password || '')
    let em = normalizeEmail(req.body?.email)
    if (u.length < 2) {
      res.status(400).json({ error: 'Username must be at least 2 characters' })
      return
    }
    if (u.toLowerCase() === ADMIN_USERNAME) {
      res.status(400).json({ error: 'That username is reserved' })
      return
    }
    if (pw.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters' })
      return
    }
    if (await findUserByUsername(u)) {
      res.status(409).json({ error: 'Username already taken' })
      return
    }
    if (await findStaffByUsername(u)) {
      res.status(409).json({ error: 'Username already taken' })
      return
    }

    const id = `s_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`
    if (!em || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) {
      em = `staff.${id}@pixdot.local`
    }
    if (await getDb().collection('users').findOne({ email: em })) {
      res.status(409).json({ error: 'That email is already in use' })
      return
    }
    if (await getDb().collection('staff').findOne({ email: em })) {
      res.status(409).json({ error: 'That email is already in use' })
      return
    }

    const row = {
      id,
      username: u,
      usernameLower: u.toLowerCase(),
      email: em,
      passwordHash: bcrypt.hashSync(pw, 10),
      role: 'staff',
      createdAt: new Date().toISOString(),
      createdBy: req.user.id,
    }
    await insertStaff(row)
    res.status(201).json({ user: publicUser(row) })
  }),
)

/**
 * Admin only: portal login for a company client (linked to clientId in your app / Mongo later).
 * Email auto-generated if omitted (login form still needs username + email + password).
 */
app.post(
  '/api/auth/client-user',
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (publicUser(req.user).role !== 'admin') {
      res.status(403).json({ error: 'Only admins can create client portal users' })
      return
    }
    const u = String(req.body?.username || '').trim()
    const pw = String(req.body?.password || '')
    const clientId = String(req.body?.clientId || '').trim()
    let em = normalizeEmail(req.body?.email)

    if (u.length < 2) {
      res.status(400).json({ error: 'Username must be at least 2 characters' })
      return
    }
    if (pw.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters' })
      return
    }
    if (!clientId) {
      res.status(400).json({ error: 'clientId is required' })
      return
    }
    if (u.toLowerCase() === ADMIN_USERNAME) {
      res.status(400).json({ error: 'That username is reserved' })
      return
    }
    if (await findUserByUsername(u)) {
      res.status(409).json({ error: 'Username already taken' })
      return
    }
    if (await findStaffByUsername(u)) {
      res.status(409).json({ error: 'Username already taken' })
      return
    }

    const id = `u_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 9)}`
    if (!em || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(em)) {
      em = `portal.${id}@pixdot.local`
    }
    if (await getDb().collection('users').findOne({ email: em })) {
      res.status(409).json({ error: 'That email is already in use' })
      return
    }
    if (await getDb().collection('staff').findOne({ email: em })) {
      res.status(409).json({ error: 'That email is already in use' })
      return
    }

    const row = {
      id,
      username: u,
      usernameLower: u.toLowerCase(),
      email: em,
      passwordHash: bcrypt.hashSync(pw, 10),
      role: 'client',
      clientId,
      createdAt: new Date().toISOString(),
    }
    await insertUser(row)
    res.status(201).json({ user: publicUser(row) })
  }),
)

function roleOf(req) {
  return publicUser(req.user)?.role
}

function canAccessClientDoc(req, clientId) {
  const r = roleOf(req)
  if (r === 'admin' || r === 'staff') return true
  if (r === 'client' && String(req.user.clientId || '') === String(clientId)) return true
  return false
}

/** List all clients — admin + staff */
app.get(
  '/api/clients',
  authMiddleware,
  asyncHandler(async (req, res) => {
    const r = roleOf(req)
    if (r !== 'admin' && r !== 'staff') {
      res.status(403).json({ error: 'Forbidden' })
      return
    }
    const clients = await listClients()
    res.json({ clients })
  }),
)

/** Single client — admin/staff any id; portal client only own clientId */
app.get(
  '/api/clients/:id',
  authMiddleware,
  asyncHandler(async (req, res) => {
    const id = String(req.params.id || '').trim()
    if (!id) {
      res.status(400).json({ error: 'Invalid id' })
      return
    }
    if (!canAccessClientDoc(req, id)) {
      res.status(403).json({ error: 'Forbidden' })
      return
    }
    const client = await findClientById(id)
    if (!client) {
      res.status(404).json({ error: 'Client not found' })
      return
    }
    res.json({ client })
  }),
)

/** Create client — admin only; body is full client record (id, name, portal, …) */
app.post(
  '/api/clients',
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (roleOf(req) !== 'admin') {
      res.status(403).json({ error: 'Only admins can create clients' })
      return
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {}
    const id = String(body.id || '').trim()
    const name = String(body.name || '').trim()
    if (!id || !name) {
      res.status(400).json({ error: 'id and name are required' })
      return
    }
    if (await findClientById(id)) {
      res.status(409).json({ error: 'A client with this id already exists' })
      return
    }
    const now = new Date().toISOString()
    const doc = {
      id,
      name,
      initials: String(body.initials || '')
        .trim()
        .toUpperCase()
        .slice(0, 4),
      serviceIds: Array.isArray(body.serviceIds) ? body.serviceIds : [],
      requirements:
        body.requirements && typeof body.requirements === 'object'
          ? {
              notes: typeof body.requirements.notes === 'string' ? body.requirements.notes : '',
              items: Array.isArray(body.requirements.items) ? body.requirements.items : [],
            }
          : { notes: '', items: [] },
      portal:
        body.portal && typeof body.portal === 'object'
          ? {
              companyTagline: body.portal.companyTagline ?? null,
              ownerPhones: Array.isArray(body.portal.ownerPhones) ? body.portal.ownerPhones : [],
              ownerEmails: Array.isArray(body.portal.ownerEmails) ? body.portal.ownerEmails : [],
              socialLinks: Array.isArray(body.portal.socialLinks) ? body.portal.socialLinks : [],
            }
          : {
              companyTagline: null,
              ownerPhones: [],
              ownerEmails: [],
              socialLinks: [],
            },
      uploads: Array.isArray(body.uploads) ? body.uploads : [],
      createdAt: now,
      updatedAt: now,
    }
    await insertClient(doc)
    res.status(201).json({ client: doc })
  }),
)

/** Replace client document — admin only */
app.put(
  '/api/clients/:id',
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (roleOf(req) !== 'admin') {
      res.status(403).json({ error: 'Only admins can update clients' })
      return
    }
    const id = String(req.params.id || '').trim()
    const existing = await findClientById(id)
    if (!existing) {
      res.status(404).json({ error: 'Client not found' })
      return
    }
    const body = req.body && typeof req.body === 'object' ? req.body : {}
    const now = new Date().toISOString()
    const doc = {
      id,
      name: String(body.name ?? existing.name).trim() || existing.name,
      initials: String(body.initials ?? existing.initials)
        .trim()
        .toUpperCase()
        .slice(0, 4),
      serviceIds: Array.isArray(body.serviceIds) ? body.serviceIds : existing.serviceIds || [],
      requirements:
        body.requirements && typeof body.requirements === 'object'
          ? {
              notes: typeof body.requirements.notes === 'string' ? body.requirements.notes : '',
              items: Array.isArray(body.requirements.items) ? body.requirements.items : [],
            }
          : existing.requirements || { notes: '', items: [] },
      portal:
        body.portal && typeof body.portal === 'object'
          ? {
              companyTagline: body.portal.companyTagline ?? null,
              ownerPhones: Array.isArray(body.portal.ownerPhones) ? body.portal.ownerPhones : [],
              ownerEmails: Array.isArray(body.portal.ownerEmails) ? body.portal.ownerEmails : [],
              socialLinks: Array.isArray(body.portal.socialLinks) ? body.portal.socialLinks : [],
            }
          : existing.portal,
      uploads: Array.isArray(body.uploads) ? body.uploads : existing.uploads || [],
      createdAt: existing.createdAt || now,
      updatedAt: now,
    }
    await replaceClient(id, doc)
    res.json({ client: doc })
  }),
)

app.delete(
  '/api/clients',
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (roleOf(req) !== 'admin') {
      res.status(403).json({ error: 'Only admins can delete all clients' })
      return
    }
    if (String(req.query.all || '') !== '1') {
      res.status(400).json({ error: 'Use ?all=1 to delete every client' })
      return
    }
    await deleteAllClients()
    res.json({ ok: true })
  }),
)

app.delete(
  '/api/clients/:id',
  authMiddleware,
  asyncHandler(async (req, res) => {
    if (roleOf(req) !== 'admin') {
      res.status(403).json({ error: 'Only admins can delete clients' })
      return
    }
    const id = String(req.params.id || '').trim()
    const existing = await findClientById(id)
    if (!existing) {
      res.status(404).json({ error: 'Client not found' })
      return
    }
    await deleteClientById(id)
    res.json({ ok: true })
  }),
)

app.use((err, _req, res, _next) => {
  console.error(err)
  if (res.headersSent) return
  res.status(500).json({ error: err.message || 'Internal server error' })
})

try {
  await connectDb()
  await ensurePermanentAdmin()
  app.listen(PORT, () => {
    console.log(`Pixdot auth API http://localhost:${PORT}`)
  })
} catch (e) {
  console.error(e)
  process.exit(1)
}
