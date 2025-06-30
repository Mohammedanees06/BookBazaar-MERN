const mongoose = require("mongoose");

const user = new mongoose.Schema({
    username : {
        type: String,
        required: true,
        unique: true
    },
    email   : {
        type: String,
        required: true,
        unique: true
    },
    password : {
        type:  String,
        required: true
    },
    address :{
        type: String,
        required: true
    },
   avatar : {
    type: String,
    default: "https://cdn.pixabay.com/photo/2015/10/05/22/37/blank-profile-picture-973460_1280.png"
   },
   role: {
    type: [String],
    enum: ["user", "admin"],
    default: ["user"]
  },
   favourites : {
    type: [mongoose.Schema.Types.ObjectId],
    ref: "Book"
   },
   cart : {
    type: [mongoose.Schema.Types.ObjectId],
    ref: "Book"
   },
   orders : [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "Order"
   }],
}, {timestamps: true}
);

module.exports  = mongoose.model("user", user);

