import React, { useState, useEffect } from 'react';
import axios from 'axios';
import BookCard from '../BookCard/BookCard';
import Loader from '../Loader/Loader';

const RecentlyAdded = () => {
  const [Data, setData] = useState([]);

  useEffect(() => {
    const fetch = async () => {
      const response = await axios.get("http://localhost:3000/api/v1/getrecentbooks");
      console.log(response.data.data.books);
      setData(response.data.data.books);
    };
    fetch();
  }, []);

  return (
    <div className="mt-10 mb-26 px-6 sm:px-10 py-4">
      <h1 className="text-3xl font-bold text-yellow-500 mb-6">Recently Added Books</h1>

      {Data.length === 0 ? (
        <div className="flex justify-center items-center h-64">
          <Loader />
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
          {Data.map((item, i) => (
            <BookCard key={i} data={item} />
          ))}
        </div>
      )}
    </div>
  );
};

export default RecentlyAdded;
