const express = require('express');
const jwt = require('jsonwebtoken');
const { StreamChat } = require('stream-chat');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();

// Validate environment variables at startup
if (!process.env.STREAM_API_KEY || !process.env.STREAM_API_SECRET || !process.env.JWT_SECRET) {
    console.error('Missing Stream API key or secret in environment variables');
    process.exit(1);  // Exit process if critical env vars are missing
}

// Initialize the Express app
const app = express();
const port = process.env.PORT || 3000;

// Stream Chat client initialization
let serverClient;
try {
    serverClient = StreamChat.getInstance(process.env.STREAM_API_KEY, process.env.STREAM_API_SECRET);
} catch (error) {
    console.error('Error initializing StreamChat client:', error);
    process.exit(1);  // Exit if there's an issue with initializing the client
}

// Middleware
app.use(helmet());  // Secure HTTP headers
app.use(cors());    // Enable CORS for cross-origin requests
app.use(express.json());  // Parse incoming JSON requests

// JWT Token generation route for the backend
app.post('/generate-api-key', (req, res) => {
    const payload = { role: 'admin' };  // You can modify this payload
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });  // Generate JWT
    return res.json({ apiKey: token });
});

// Middleware to verify the JWT in requests
const verifyJWT = (req, res, next) => {
    const token = req.headers['authorization'];
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

// Token generation route
app.get('/token', (req, res, next) => {
    try {
        const { userId } = req.query;
        
        // Validate userId is provided and valid
        if (!userId || typeof userId !== 'string' || userId.trim().length === 0) {
            const error = new Error('Invalid or missing User ID');
            error.status = 400;
            throw error;
        }
        
        // Additional validation (optional) - Check for length or characters
        if (userId.length < 5 || !/^[\w-]+$/.test(userId)) {
            const error = new Error('User ID must be at least 5 characters long and contain only letters, numbers, or underscores.');
            error.status = 400;
            throw error;
        }

        // Generate the token using StreamChat
        const token = serverClient.createToken(userId);
        
        // Handle case where token generation fails (unlikely, but possible)
        if (!token) {
            const error = new Error('Failed to generate token');
            error.status = 500;
            throw error;
        }

        return res.json({ token });

    } catch (error) {
        next(error);  // Pass the error to the error handler middleware
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
