const fs = require("fs");

const databaseName = process.env.MONGO_DBNAME;
const authenticationDatabase = process.env.MONGO_AUTHSOURCE;
const username = process.env.MONGO_USER;
const password = fs.readFileSync(process.env.MONGO_PASS_FILE, "utf8").trim();

db.getSiblingDB(authenticationDatabase).createUser({
  user: username,
  pwd: password,
  roles: [
    "clusterMonitor",
    { db: databaseName, role: "dbOwner" },
    { db: `${databaseName}_stat`, role: "dbOwner" },
    { db: `${databaseName}_audit`, role: "dbOwner" },
    { db: `${databaseName}_restore`, role: "dbOwner" },
  ],
});
