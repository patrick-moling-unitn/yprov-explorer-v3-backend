How to set a user as administrator from docker

docker exec -it mongodb mongosh -u admin -p INSERT_MONGO_DB_PASSWORD --authenticationDatabase admin

use explorer_db

db.authenticatedusers.updateOne(
  { email: "target.admin@gmail.com" },
  { $set: { administrator: true } }
)

To set new superAdmin variable

db.authenticatedusers.updateMany(
  { superAdministrator: { $exists: false } },
  { $set: { superAdministrator: false } }
)