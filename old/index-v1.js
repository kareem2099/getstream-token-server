const express = require('express');
const { StreamChat } = require('stream-chat');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3008;

const serverClient = StreamChat.getInstance(process.env.STREAM_API_KEY, process.env.STREAM_API_SECRET);

app.get('/token', (req, res) => {
    const { userId } = req.query;
    if (!userId) {
        return res.status(400).send('User ID is required');
    }

    const token = serverClient.createToken(userId);
    res.send({ token });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
