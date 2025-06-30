const router = require("express").Router(); // import router from express
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { authenticateToken } = require("./userAuth");

// signup
router.post("/signup", async (req, res) => {
  try {
    const { username, email, password, address } = req.body;

    if (username.length < 4) {
      return res
        .status(400)
        .json({ message: "Username must be at least 4 characters long" });
    }

    const existingUsername = await User.findOne({ username: username });
    if (existingUsername) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const existingEmail = await User.findOne({ email: email });
    if (existingEmail) {
      return res.status(400).json({ message: "Email already exists" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters long" });
    }

    const hashPass = await bcrypt.hash(password, 10);
    const role = ["user"];

    const newUser = new User({
      username: username,
      email: email,
      password: hashPass,
      address: address,
      role: role,
    });

    await newUser.save();
    res.status(201).json({ message: "User created successfully" });
    console.log("Signup request body:", req.body);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// signin
router.post("/signin", async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log("Request Body:", req.body);

    const existingUser = await User.findOne({ username });
    console.log("Found User:", existingUser);

    if (!existingUser) {
      return res.status(400).json({ message: "User not found" });
    }

    bcrypt.compare(password, existingUser.password, (err, data) => {
      if (err) {
        console.error("Signin Error:", err);
        return res.status(500).json({ message: "Internal server error" });
      }

      if (data) {
        const authClaims = [
          { name: existingUser.username },
          { role: existingUser.role },
        ];
        const token = jwt.sign({ authClaims }, "bookStore123", {
          expiresIn: "30d",
        });
        return res
          .status(200)
          .json({
            id: existingUser._id,
            role: existingUser.role,
            token: token,
          });
      } else {
        return res.status(400).json({ message: "Invalid password" });
      }
    });
  } catch (error) {
    console.error("Signin Error:", error);
    res.status(500).json({ message: error.message });
  }
});

//get user info
router.get("/getuserinfo", authenticateToken, async (req, res) => {
  try {
    const id = req.headers.id; // ✅ Get user ID from decoded token
    const data = await User.findById(id).select("-password");
    res.status(200).json({ status: "success", data }); ;
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


//update address
router.put("/updateaddress", authenticateToken, async (req, res) => {
  try {
    const { id } = req.headers;
    const { address } = req.body;
    await User.findByIdAndUpdate(id, {address: address });
    return res.status(200).json({ message: "Address updated successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
})

//  Export the router
module.exports = router;
