const router = require("express").Router(); // import router from express
const User = require("../models/user");
const { authenticateToken } = require("./userAuth");

//add book to favourite

router.put("/addfavourite", authenticateToken, async (req, res) => {
  try {
    const { bookid, id } = req.headers;

    
    if (!bookid) {
      return res.status(400).json({ message: "bookid is required" });
    }

    const userData = await User.findById(id);
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }
    const isBookFavourite = userData.favourites.includes(bookid);

    if (isBookFavourite) {
      return res.status(400).json({ message: "Book already in favourite" });
    }

    await User.findByIdAndUpdate(id, { $push: { favourites: bookid } });
    return res
      .status(200)
      .json({ message: "Book added to favourite successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.put("/deletefavourite", authenticateToken, async (req, res) => {
  try {
    const { bookid, id } = req.headers;

    if (!bookid) {
      return res.status(400).json({ message: "bookid is required" });
    }

    const userData = await User.findById(id);
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }
    const isBookFavourite = userData.favourites.includes(bookid);

    if (isBookFavourite) {
      await User.findByIdAndUpdate(id, { $pull: { favourites: bookid } });
    }
    return res
      .status(200)
      .json({ message: "Book deleted from favourite successfully" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get("/getfavouritebooks", authenticateToken, async (req, res) => {
  try {
    const { id } = req.headers;

    const userData = await User.findById(id).populate("favourites");
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }
    const favouriteBooks = userData.favourites;
    return res.json({
      status: "success",
      data: {
        favouriteBooks,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
