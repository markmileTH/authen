const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const cors = require('cors');

let redisClient = redis.createClient({
  retry_strategy: function(options) {
    if (options.attempt > 10) {
      // Stop retrying after 10 attempts
      return undefined;
    }
    // Retry connection after 1000ms
    return Math.min(options.attempt * 100, 3000);
  }
});

redisClient.on('error', (err) => {
  console.log("Error " + err);
});

redisClient.on('end', () => {
  console.log("Redis client connection closed");
});


const expressJwt = require('express-jwt');
const app = express();
app.use(cors());
app.use(express.json());

// Replace with your AD server endpoint
const AD_SERVER = "http://localhost:3002/authenticate"; 

// Token Secret for JWT
const JWT_SECRET = 'm4rkr0ck';

// Middleware to validate token and exclude authenticate route
app.use(expressJwt({ secret: JWT_SECRET, algorithms: ['HS256'] })
  .unless({ path: ['/authenticate', '/refresh'] }));

app.post('/authenticate', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Forward the request to the AD server
    const response = await axios.post(AD_SERVER, { username, password });

    if (response.data.success) {
      // If AD server returns success
      // Generate a JWT
      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });

      // Store JWT in Redis
      redisClient.set(username, token);

      // Send JWT to the client
      res.json({ success: true, token });
    } else {
      // If AD server returns failure
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/refresh', expressJwt({ secret: JWT_SECRET, algorithms: ['HS256'] }), (req, res) => {
  const { username } = req.user;

  // Generate a new JWT
  const newToken = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });

  // Store the new JWT in Redis
  redisClient.set(username, newToken);

  // Send the new JWT to the client
  res.json({ success: true, token: newToken });
});

app.use((err, req, res, next) => {
  if (err.name === 'UnauthorizedError') {
    // If the error is because of an invalid token, send error status and message
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

app.listen(3001, () => console.log('Auth server listening on port 3001'));
