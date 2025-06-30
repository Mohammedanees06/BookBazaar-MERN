const router = require("express").Router(); // import router from express
const User = require("../models/user");
const { authenticateToken } = require("./userAuth");
const Book = require("../models/book");
const Order = require("../models/order")


//put book to cart


router.put("/addtocart", authenticateToken, async (req, res) => {
  try {
    const { bookid, id } = req.headers;
    if (!bookid) {
      return res.status(400).json({ message: "bookid is required" });
    }
    const userData = await User.findById(id);
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }
    const isBookInCart = userData.cart.includes(bookid);
    if (isBookInCart) {
      return res
        .status(400)
        .json({ status: "success", message: "Book already in cart" });
        
    }
    await User.findByIdAndUpdate(id, { $push: { cart: bookid } });
    return res.json({
      status: "success",
      message: "Book added to cart successfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.delete(
  "/removefromcart/:bookid",
  authenticateToken,
  async (req, res) => {
    try {
      const { bookid } = req.params;
      const { id } = req.headers;
      if (!bookid) {
        return res.status(400).json({ message: "bookid is required" });
      }
      const userData = await User.findById(id);
      if (!userData) {
        return res.status(404).json({ message: "User not found" });
      }
      const isBookInCart = userData.cart.includes(bookid);
      if (!isBookInCart) {
        return res
          .status(400)
          .json({ status: "success", message: "Book not in cart" });
      }
      await User.findByIdAndUpdate(id, { $pull: { cart: bookid } });
      return res.json({
        status: "success",
        message: "Book removed from cart successfully",
      });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }
);

router.get("/getusercart", authenticateToken, async (req, res) => {
  try {
    const { id } = req.headers;
    const userData = await User.findById(id).populate("cart");
    if (!userData) {
      return res.status(404).json({ message: "User not found" });
    }

    const cart = userData.cart.reverse();
    return res.json({
      status: "success",
      data: {
        cart,
      },
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});
module.exports = router;
