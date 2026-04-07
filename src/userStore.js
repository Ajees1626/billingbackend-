import { getDb } from './db.js'

const COL = 'users'

export function normalizeEmail(email) {
  return String(email || '')
    .trim()
    .toLowerCase()
}

function lean(doc) {
  if (!doc) return null
  const { _id, passwordHash, ...rest } = doc
  return rest
}

export async function findUserById(id) {
  const s = String(id || '').trim()
  if (!s) return null
  const doc = await getDb().collection(COL).findOne({ id: s })
  return doc
}

export async function findUserByUsernameAndEmail(username, email) {
  const u = String(username || '').trim().toLowerCase()
  const e = normalizeEmail(email)
  if (!u || !e) return null
  return getDb().collection(COL).findOne({ usernameLower: u, email: e })
}

export async function findUserByEmail(email) {
  const e = normalizeEmail(email)
  if (!e) return null
  return getDb().collection(COL).findOne({ email: e })
}

export async function findUserByUsername(username) {
  const u = String(username || '').trim().toLowerCase()
  if (!u) return null
  return getDb().collection(COL).findOne({ usernameLower: u })
}

export async function insertUser(user) {
  await getDb().collection(COL).insertOne(user)
}

export async function replaceUserById(id, doc) {
  await getDb().collection(COL).replaceOne({ id }, doc, { upsert: true })
}

export function publicUser(doc) {
  if (!doc) return null
  const role = doc.role === 'admin' ? 'admin' : doc.role === 'staff' ? 'staff' : 'client'
  return {
    id: doc.id,
    username: doc.username,
    email: doc.email,
    createdAt: doc.createdAt,
    role,
    clientId: role === 'client' && doc.clientId ? String(doc.clientId) : null,
  }
}
