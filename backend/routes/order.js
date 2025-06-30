const { authenticateToken } = require("./userAuth");
const Book = require("../models/book");
const Order = require("../models/order")
const router = require("express").Router();
const User = require("../models/user");
const mongoose = require("mongoose");


// router.post("/placeorder", authenticateToken, async (req, res) => {
//   try {
//     const  {id} = req.headers;
//     const { order } = req.body;
//     console.log("User ID:", id);
//     console.log("Order data:", order);

//     const user = await User.findById(id);
//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     for (const orderData of order) {
//       console.log("Processing order item:", orderData);
//       const newOrder = new Order({
//         user: id,
//         // book: orderData._id,
//         books: orderData._id,
//         status: "order placed",
//       });
//       const orderDataFromDB = await newOrder.save();

//       await User.findByIdAndUpdate(id, {
//         $push: { orders: orderDataFromDB._id },
//         $pull: { cart: orderData._id },
//       });
//     }

//     return res.status(200).json({ message: "Order placed successfully" });
//   } catch (error) {
//     console.error("Error in /placeorder:", error);
//     res.status(500).json({ message: error.message });
//   }
// });


router.post("/placeorder", authenticateToken, async (req, res) => {
  try {
    const  {id} = req.headers;
    const { order } = req.body;
    console.log("User ID:", id);
    console.log("Order data:", order);

    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    for (const orderData of order) {
      console.log("Processing order item:", orderData);
      console.log("Book ID to save:", orderData._id);  // ← ADD THIS
      
      const newOrder = new Order({
        user: id,
        books: [orderData._id],
        status: "order placed",
      });
      
      console.log("Order before save:", newOrder);  // ← ADD THIS
      const orderDataFromDB = await newOrder.save();
      console.log("Order after save:", orderDataFromDB);  // ← ADD THIS

      await User.findByIdAndUpdate(id, {
        $push: { orders: orderDataFromDB._id },
        $pull: { cart: orderData._id },
      });
    }

    return res.status(200).json({ message: "Order placed successfully" });
  } catch (error) {
    console.error("Error in /placeorder:", error);
    res.status(500).json({ message: error.message });
  }
});

// router.get("/getordershistory", authenticateToken, async (req, res) => {
//   try {
//     const {id} = req.headers;

//     // Get orders for current user and populate related data
//     const userOrders = await User.findById(id).populate({
//       path: "orders",
//       populate: { path: "book",},
//      }
//     );

//     const orderData = userOrders.orders.reverse();

//     return res.json({
//       status: "success",
//       data: orderData ,
//     });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// });

router.get("/getordershistory", authenticateToken, async (req, res) => {
  try {
    const {id} = req.headers;  // ← Change this line
    
    const orders = await Order.find({ user: id })
      .populate({
        path: "books",
        model: "Book"
      })
      .sort({ createdAt: -1 });
      
    console.log("Orders with populated books:", JSON.stringify(orders, null, 2));
    res.json({ status: "success", data: orders });
  } catch (error) {
    console.error("Error in getordershistory:", error);
    res.status(500).json({ message: error.message });
  }
});





// router.get("/getallorders", authenticateToken, async (req, res) => {
//   try {
//     // Admin or authorized user can get all orders
//     const allOrders = await Order.find()
//     .populate({ path: "books" })
//       .populate({ path: "user",})
//       .sort({ createdAt: -1 });

//     return res.json({
//       status: "success",
//       data: allOrders ,
//     });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// });

router.get("/getallorders", authenticateToken, async (req, res) => {
  try {
    const allOrders = await Order.find()
      .populate({ 
        path: "books",
        model: "Book"
      })
      .populate({ 
        path: "user",
        model: "user"  // Change "User" to "user" (lowercase)
      })
      .sort({ createdAt: -1 });

    return res.json({
      status: "success",
      data: allOrders,
    });
  } catch (error) {
    console.error("❌ Error in getallorders:", error);
    res.status(500).json({ message: error.message });
  }
});




router.put("/updateorderstatus/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    await Order.findByIdAndUpdate(id, { status });

    return res.status(200).json({
      status: "success",
      message: "Order status updated successfully",
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
