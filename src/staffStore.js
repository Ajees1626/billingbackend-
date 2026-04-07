import { getDb } from './db.js'

const COL = 'staff'

export async function findStaffById(id) {
  const s = String(id || '').trim()
  if (!s) return null
  return getDb().collection(COL).findOne({ id: s })
}

export async function findStaffByUsername(username) {
  const u = String(username || '').trim().toLowerCase()
  if (!u) return null
  return getDb().collection(COL).findOne({ usernameLower: u })
}

export async function insertStaff(doc) {
  await getDb().collection(COL).insertOne(doc)
}
