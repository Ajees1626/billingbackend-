import { getDb } from './db.js'

const COL = 'clients'

function lean(doc) {
  if (!doc) return null
  const { _id, ...rest } = doc
  return rest
}

export async function listClients() {
  const docs = await getDb()
    .collection(COL)
    .find({})
    .sort({ updatedAt: -1 })
    .toArray()
  return docs.map(lean)
}

export async function findClientById(id) {
  const pid = String(id || '').trim()
  if (!pid) return null
  const doc = await getDb().collection(COL).findOne({ id: pid })
  return lean(doc)
}

export async function insertClient(doc) {
  await getDb().collection(COL).insertOne(doc)
}

export async function replaceClient(id, doc) {
  const pid = String(id || '').trim()
  const r = await getDb().collection(COL).replaceOne({ id: pid }, doc)
  return r.matchedCount > 0
}

export async function deleteClientById(id) {
  const pid = String(id || '').trim()
  await getDb().collection(COL).deleteOne({ id: pid })
}

export async function deleteAllClients() {
  await getDb().collection(COL).deleteMany({})
}
