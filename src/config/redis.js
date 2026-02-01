import { createClient } from "redis"
import { REDIS_URL } from "./env.js";


const redisURL = REDIS_URL;

if(!redisURL) {
    console.error("REDIS_URL is missing");
    process.exit(1)
}

export const redisClient = createClient({url: redisURL})

redisClient.on('error', (err) => console.log('Redis Client Error', err));

redisClient
    .connect()
    .then(() => console.log("Connected to Redis"))
    .catch(console.error);
 
    

