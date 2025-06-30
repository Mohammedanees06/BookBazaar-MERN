const mongoose = require("mongoose");


const orderSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "user", // ensure this matches your user model export
     
    },
    books: [{
      type: mongoose.Schema.Types.ObjectId,
      ref: "Book", // ensure this matches your book model export
     
    }],
    status: {
      type: String,
      default: "order placed",
      enum: ["order placed", "processing", "shipped", "delivered", "cancelled"],
    },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Order", orderSchema);
