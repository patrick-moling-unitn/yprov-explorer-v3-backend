How to set a user as administrator from docker

docker exec -it mongodb mongosh -u admin -p INSERT_MONGO_DB_PASSWORD --authenticationDatabase admin

use explorer_db

db.authenticatedusers.updateOne(
  { email: "target.admin@gmail.com" },
  { $set: { administrator: true } }
)