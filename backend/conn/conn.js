const mongoose = require('mongoose');

const conn = async () => {
    try {
        await mongoose.connect(process.env.URI);
        console.log('MongoDB connected');
    } catch (error) {
        console.log('MongoDB connection failed');
    }
}

conn();
module.exports = conn;
