const express = require('express');
const jwt = require('jsonwebtoken');
const { StreamChat } = require('stream-chat');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

// Validate environment variables at startup
if (!process.env.STREAM_API_KEY || !process.env.STREAM_API_SECRET || !process.env.JWT_SECRET) {
    console.error('Missing Stream API key, secret, or JWT secret in environment variables');
    process.exit(1);
}

// Initialize the Express app
const app = express();
const port = process.env.PORT || 3001;

// Stream Chat client initialization
let serverClient;
try {
    serverClient = StreamChat.getInstance(process.env.STREAM_API_KEY, process.env.STREAM_API_SECRET);
} catch (error) {
    console.error('Error initializing StreamChat client:', error);
    process.exit(1);
}

// Middleware
app.use(helmet());  // Secure HTTP headers
app.use(cors());    // Enable CORS for cross-origin requests
app.use(express.json());  // Parse incoming JSON requests

// Rate limiter for /generate-api-key route
const apiKeyRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

app.post('/generate-api-key', apiKeyRateLimiter, (req, res) => {
    console.log("API Key route hit");
    const payload = { role: 'admin' };  // Modify payload as needed
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });
    return res.json({ apiKey: token });
});

// Middleware to verify the JWT in requests
const verifyJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];  // Extract token from 'Bearer <token>'
    if (!token) {
        return res.status(403).json({ error: 'No token provided' });
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ error: 'Unauthorized' });
        }
        req.user = decoded;
        next();
    });
};

// Token generation route with JWT authentication
app.get('/token', verifyJWT, (req, res, next) => {
    try {
        const { userId } = req.query;
        
        if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
            return res.status(400).json({ error: 'Invalid or missing User ID' });
        }
        
        if (userId.length < 5 || !/^[\w-]+$/.test(userId)) {
            return res.status(400).json({ error: 'User ID must be at least 5 characters long and contain only letters, numbers, or underscores.' });
        }

        const token = serverClient.createToken(userId);
        
        if (!token) {
            return res.status(500).json({ error: 'Failed to generate token' });
        }

        return res.json({ token });

    } catch (error) {
        next(error);
    }
});

// Centralized error handler middleware
app.use((err, req, res, next) => {
    console.error('Error:', err.message || err);

    const status = err.status || 500;
    const errorMessage = err.message || 'Internal Server Error';

    res.status(status).json({ error: errorMessage });
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
