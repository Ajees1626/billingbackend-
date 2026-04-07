import { MongoClient } from 'mongodb'

let client = null
let database = null

const DEV_LOCAL_URI = 'mongodb://127.0.0.1:27017'

export async function connectDb() {
  let uri = String(process.env.MONGODB_URI || '').trim()
  if (!uri) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error(
        'MONGODB_URI is required in production. Set it in backend/.env (see .env.example).',
      )
    }
    uri = DEV_LOCAL_URI
    console.warn(
      `[pixdot] MONGODB_URI empty — using ${DEV_LOCAL_URI}. For Atlas, set MONGODB_URI in backend/.env`,
    )
  }
  const dbName = String(process.env.MONGODB_DB_NAME || 'pixdot').trim() || 'pixdot'

  client = new MongoClient(uri)
  try {
    await client.connect()
  } catch (err) {
    const msg = err?.message || String(err)
    throw new Error(
      `Cannot connect to MongoDB (${msg}). If using Atlas, put MONGODB_URI in backend/.env. If local, install/start MongoDB on port 27017, or run: mongod`,
    )
  }
  database = client.db(dbName)

  await database.collection('users').createIndex({ id: 1 }, { unique: true })
  await database.collection('users').createIndex({ email: 1 }, { unique: true })
  await database.collection('users').createIndex({ usernameLower: 1 }, { unique: true })

  await database.collection('staff').createIndex({ id: 1 }, { unique: true })
  await database.collection('staff').createIndex({ usernameLower: 1 }, { unique: true })
  await database.collection('staff').createIndex({ email: 1 }, { unique: true })

  await database.collection('clients').createIndex({ id: 1 }, { unique: true })

  console.log(`MongoDB connected → "${dbName}"`)
  return database
}

export function getDb() {
  if (!database) throw new Error('Database not initialized')
  return database
}

export async function closeDb() {
  database = null
  if (client) {
    await client.close()
    client = null
  }
}
