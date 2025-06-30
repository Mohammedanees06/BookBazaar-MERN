import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import Loader from "../Loader/Loader";
import { GrLanguage } from "react-icons/gr";
import { FaShoppingCart, FaHeart, FaEdit, FaTrash } from "react-icons/fa";
import { useSelector } from "react-redux";
import { Link } from "react-router-dom";





const ViewBookDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const isLoggedIn = useSelector((state) => state.auth.isLoggedIn);
  const role = useSelector((state) => state.auth.role);

  useEffect(() => {
    const fetch = async () => {
      try {
        const response = await axios.get(
          `http://localhost:3000/api/v1/getbookbyid/${id}`
        );
        setData(response.data.data.book);
      } catch (error) {
        console.error("Failed to fetch book:", error);
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, [id]);

 
  const headers = {
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    id: localStorage.getItem("id"),
    bookid: id,
  };
  const handleAddToCart = async () => {
    try {
      const response = await axios.put(
        `http://localhost:3000/api/v1/addtocart`,
        { bookId: id },  // <-- important to send bookId here
        { headers }
      );
      alert("Book added to cart successfully!");
    } catch (error) {
      if (error.response?.data?.message === "Book already in cart") {
        alert("This book is already in your cart.");
      } else {
      console.error("Failed to add to cart:", error.response?.data || error.message);
      alert("Failed to add to cart.");
      }
    }
  };
  
  const handleFavorites = async () => {
    try {
      const response = await axios.put(
        `http://localhost:3000/api/v1/addfavourite`,
        { bookId: id },  
        { headers }
        
      );
      alert("Book added to favorites successfully!");
    
    } catch (error) {
      if (error.response?.data?.message === "Book already in favourite") {
        alert("This book is already in your favorites.");
      } else {
        console.error("Failed to add to favorites:", error.response?.data || error.message);
        alert("Failed to add to favorites.");
      }
     
    }
  };
  
  

  const handleDelete = async () => {
    const confirmDelete = window.confirm("Are you sure you want to delete this book?");
    if (!confirmDelete) return;

    try {
     const response = await axios.delete(`http://localhost:3000/api/v1/deletebook` , {headers});
     console.log(response);
      alert(response.data.message);
      navigate("/all-books"); // Adjust this path based on your routing
    } catch (error) {
      console.error("Failed to delete book:", error);
      alert("Failed to delete the book.");
    }
  };

  if (loading) return <Loader />;

  return (
    <div className="  min-h-screen w-full px-4 md:px-12 py-8 bg-zinc-900 text-white flex flex-col md:flex-row gap-6 md:gap-8">
      {/* Book Image */}
      <div className="bg-zinc-100 rounded p-4 w-full md:w-1/2 flex justify-center items-center">
        <img
          src={data?.url}
          alt={data?.title}
          className="rounded w-full max-w-[400px] max-h-[500px] object-contain"
        />
      </div>

      {/* Book Details */}
      <div className="bg-zinc-800 rounded p-6 w-full md:w-1/2 space-y-4">
        <h1 className="text-2xl md:text-3xl font-bold">{data?.title}</h1>
        <p className="text-gray-300 text-sm md:text-base italic">
          by {data?.author}
        </p>
        <p className="text-base md:text-lg leading-relaxed">
          {data?.description}
        </p>

        <p className="flex items-center gap-2 text-base md:text-lg mt-2">
          <GrLanguage className="text-xl" />
          <span>{data?.language}</span>
        </p>

        <div className="text-sm md:text-base space-y-2 pt-4">
          <p>
            <span className="font-semibold">Price:</span> ₹{data?.price}
          </p>
          <p>
            <span className="font-semibold">Category:</span> {data?.category}
          </p>
          <p>
            <span className="font-semibold">Language:</span> {data?.language}
          </p>
        </div>

        {/* Action Buttons */}
        {isLoggedIn && role === "user" && (
          <div className="flex flex-col sm:flex-row gap-4 pt-6">
            <button className="bg-blue-500 text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-blue-600 transition"
            onClick={handleAddToCart}>
              <FaShoppingCart />
              Add to Cart
            </button>
            <button className="bg-pink-500 text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-pink-600 transition"
            onClick={handleFavorites}
            >
              <FaHeart />
              Add to Favorites
            </button>
          </div>
        )}

        {isLoggedIn && role === "admin" && (
          <div className="flex flex-col sm:flex-row gap-4 pt-6">
            <Link to={`/updateBook/${id}`}
              
              className="bg-yellow-500 text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-yellow-600 transition"
            >
              <FaEdit />
              Edit Book
            </Link>
            <button
              onClick={handleDelete}
              className="bg-red-500 text-white px-4 py-2 rounded-md flex items-center gap-2 hover:bg-red-600 transition"
            >
              <FaTrash />
              Delete Book
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default ViewBookDetails;
