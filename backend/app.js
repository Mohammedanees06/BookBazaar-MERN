const express = require('express');
const app = express();
const cors = require('cors');
require('dotenv').config(); //  to configure env 
require("./conn/conn") // connect to database
const user=require('./routes/user');
const Books = require('./routes/book');
const Favourite = require("./routes/favourite");
const Cart = require("./routes/cart");
const orderRoutes = require("./routes/order");

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use("/api/v1", user);
app.use("/api/v1", Books);
app.use("/api/v1", Favourite);
app.use("/api/v1", Cart);
app.use("/api/v1", orderRoutes);


// Basic route
app.get('/', (req, res) => {
    res.send('Hello World');
});

// 404 handler
app.use((req, res, next) => {
    res.status(404).json({ message: 'Route not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(err.status || 500).json({
        message: err.message || 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err : {}
    });
});

app.listen(process.env.PORT || 3000, () => {
    console.log(`Server is running on port ${process.env.PORT || 3000}`);
});

