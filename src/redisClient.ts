import Redis from 'ioredis';

const redis = new Redis({
  host: 'localhost', // Use your Redis server address
  port: 6379
});

redis.on('connect', () => {
  console.log('Connected to Redis');
});

redis.on('error', (err) => {
  console.error('Redis error', err);
});

export default redis;
