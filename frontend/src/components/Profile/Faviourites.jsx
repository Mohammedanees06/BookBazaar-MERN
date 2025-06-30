import React, { useState, useEffect } from 'react';
import axios from 'axios';
import BookCard from '../BookCard/BookCard';




const Favourites = () => {
  const [favouritebooks, setFavouritebooks] = useState([]);

  const headers = {
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    id: localStorage.getItem("id"),
  };

  useEffect(() => {
    const fetch = async () => {
      try {
        const response = await axios.get("http://localhost:3000/api/v1/getfavouritebooks", { headers });
        console.log("API full response:", response);
        console.log("API response data:", response.data);
  
        
        const favs = response.data.data?.favouriteBooks || [];
        setFavouritebooks(Array.isArray(favs) ? favs : []);
      } catch (error) {
        console.error("Failed to fetch favourite books:", error.response?.data || error.message);
        setFavouritebooks([]);
      }
    };
    fetch();
  }, [favouritebooks]);
  

  return (
    <div className="grid grid-cols-1 mt-4  sm:grid-cols-3 gap-6 p-4 max-w-5xl mx-auto">
  {favouritebooks.length > 0 ? (
    favouritebooks.map((item, i) => (
      <div
        key={i}
        className="border rounded shadow p-4 max-w-xs mx-auto"
      >
        <BookCard data={item} favourite={true}/>
      </div>
    ))
  ) : (
    <p className="text-center text-4xl py-40 justify-center items-center text-gray-400 col-span-full">No favourite books found.</p>
  )}
</div>

  
  
  
  );
};

export default Favourites;
