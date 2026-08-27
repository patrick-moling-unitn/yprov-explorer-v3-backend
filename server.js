const express = require('express')
const cors = require('cors')
const { MongoClient } = require('mongodb')
require('dotenv').config()

const app = express()

app.use(cors())
app.use(express.json())

const client = new MongoClient(process.env.MONGO_URI)

async function start() {
  await client.connect()

  console.log('MongoDB connected')

  const db = client.db(process.env.MONGO_DB_NAME)
  const users = db.collection('users')

  app.get('/api/users', async (req, res) => {
    const result = await users.find().toArray()
    res.json(result)
  })

  app.post('/api/users', async (req, res) => {
    const result = await users.insertOne(req.body)
    res.json(result)
  })

  app.listen(8010, () => {
    console.log('Backend running on http://localhost:8010')
  })
}

start().catch(console.error)
