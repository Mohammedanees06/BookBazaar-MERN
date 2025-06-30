// Import the jsonwebtoken library to work with JWT tokens
const jwt = require("jsonwebtoken");

// Middleware function to check if the user is authenticated
const authenticateToken = (req, res, next) => {
    // Get the 'authorization' header from the request
    const authHeader = req.headers["authorization"];
    
    // Extract the token part from the header (format is usually: "Bearer <token>")
    const token = authHeader && authHeader.split(" ")[1]; 

    // If there's no token, respond with "Unauthorized"
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    }

    // Verify the token using the secret key "bookstore123"
    jwt.verify(token, "bookStore123", (err, user) => {
        // If token is invalid or expired, respond with "Unauthorized"
        if (err) {
            return res.status(401).json({ message: "Unauthorized" });
        }

        // If token is valid, store user info in req.user
        req.user = user;

        // Move to the next middleware or route handler
        next();
    });
}

// Export the function so it can be used in other files
module.exports = { authenticateToken };
