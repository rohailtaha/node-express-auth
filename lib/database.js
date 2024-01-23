const { MongoClient } = require('mongodb');

let db;

async function getDatabase() {
  if (!db) {
    const mongoClient = new MongoClient(process.env.DATABASE_CONNECTION);
    await mongoClient.connect();
    db = mongoClient.db(process.env.DATABASE_NAME);
  }

  return db;
}

module.exports = {
  getDatabase,
};
