import React from "react";
import { Link } from "react-router-dom";
import { FaTrash } from "react-icons/fa";
import axios from "axios";
import { FaBook } from "react-icons/fa";
import { useState } from "react";

const BookCard = ({ data, favourite }) => {
  const headers = {
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    id: localStorage.getItem("id"),
    bookid: data._id,
  };

  const [imgError, setImgError] = useState(false);
  const handleRemoveFromFavourites = async () => {
    try {
      const response = await axios.put(
        `http://localhost:3000/api/v1/deletefavourite`,
        {
          bookid: data._id,
        },
        { headers }
      );
      alert(response.data.message);
      // Optionally refresh or notify parent component to re-render
    } catch (error) {
      console.error("Failed to remove from favourites:", error);
    }
  };

  return (
    <div className="bg-black text-white shadow-md rounded-lg overflow-hidden flex flex-col transition-transform hover:scale-105 h-full">
      <Link to={`/viewbookdetails/${data._id}`} className="w-full">
        {!imgError ? (
          <img
            src={data.url}
            alt={data.title}
            className="h-62 w-full "
            onError={() => setImgError(true)} // fallback on error
          />
        ) : (
          <div className="h-62 w-full flex items-center justify-center bg-gray-100 text-gray-500 text-6xl">
            <FaBook />
          </div>
        )}

        <div className="p-4 flex flex-col justify-between flex-1">
          <div>
            <h2 className="text-lg font-semibold mb-1 line-clamp-1">
              {data.title}
            </h2>
            <p className="text-sm text-gray-400 mb-2 line-clamp-1">
              {data.author}
            </p>
            <p className="text-sm text-gray-300 line-clamp-2">
              {data.description}
            </p>
          </div>
          <div className="mt-3">
            <span className="text-yellow-400 font-bold text-base">
              ₹{data.price}
            </span>
          </div>
        </div>
      </Link>

      {/* Button outside Link */}
      {favourite && (
        <div className="p-4 pt-0">
          <button
            className="w-full bg-red-500 text-white px-4 py-2 rounded-md flex items-center justify-center gap-2 hover:bg-red-600 transition"
            onClick={() => handleRemoveFromFavourites(data._id)}
          >
            <FaTrash />
            Remove from favourites
          </button>
        </div>
      )}
    </div>
  );
};

export default BookCard;
