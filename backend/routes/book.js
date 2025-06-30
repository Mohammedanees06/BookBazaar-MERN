const router = require("express").Router(); // import router from express
const User = require("../models/user");
const jwt = require("jsonwebtoken");
const { authenticateToken } = require("./userAuth");
const Book = require("../models/book");
const Order = require("../models/order");
//addbook -admin
router.post("/addbook", authenticateToken, async (req, res) => {
  try {
    const { id } = req.headers;
    const user = await User.findById(id);
    if (!user || !user.role.includes("admin")) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const book = new Book({
      url: req.body.url,
      title: req.body.title,
      author: req.body.author,
      price: req.body.price,
      description: req.body.description,
      language: req.body.language,
      category: req.body.category,
    });

    await book.save();

    return res.status(200).json({ message: "Book added successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

//update-book
router.put("/updatebook", authenticateToken, async (req, res) => {
  try {
    const { bookid } = req.headers;

    await Book.findByIdAndUpdate(bookid, {
      url: req.body.url,
      title: req.body.title,
      author: req.body.author,
      price: req.body.price,
      description: req.body.description,
      language: req.body.language,
      category: req.body.category,
    });
    return res.status(200).json({ message: "Book updated successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.delete("/deletebook", authenticateToken, async (req, res) => {
  try {
    const { bookid } = req.headers;
    await Book.findByIdAndDelete(bookid);
    return res.status(200).json({ message: "Book deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get("/getallbooks", async (req, res) => {
  try {
    const books = await Book.find().sort({ createdAt: -1 }); // or remove sort if not needed
    return res.json({
      status: "success",
      data: {
        books,
      },  
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


router.get("/getrecentbooks",  async (req, res) => {
  try {
    const books = await Book.find().sort({ createdAt: -1 }).limit(4);
    return res.json({
      status: "success",
      data: {
        books,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get("/getbookbyid/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const book = await Book.findById(id);
    return res.json({
      status: "success",
      data: {
        book,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});


module.exports = router;
