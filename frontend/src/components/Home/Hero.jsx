import React from 'react';
import { Link } from 'react-router-dom';

const Hero = () => {
  return (
    <div className="hero min-h-screen  flex flex-col lg:flex-row bg-zinc-900 text-yellow-500">
      {/* Left Section */}
      <div className="w-full lg:w-1/2 p-8 flex flex-col items-center lg:items-start justify-center text-center lg:text-left">
        <h1 className="text-4xl lg:text-6xl font-bold">
          Welcome to BookBazaar
        </h1>
        <p className="text-xl lg:text-2xl mt-4 font-medium">
          Discover a world of books and stories
        </p>
        <Link to="/all-books">
        <button className="mt-8 px-6 py-3 bg-yellow-500 text-black text-lg border-2 border-yellow-500 rounded hover:bg-black hover:text-yellow-100 transition">
          Discover Books
        </button>
        </Link>
      </div>

      {/* Right Section (Image) */}
      <div className="w-full lg:w-1/2">
        <img
          src="src/images/hero-cont.png" // ✅ Only if placed inside public/images
          alt="Book Illustration"
          className="w-full h-full object-cover"
        />
      </div>
    </div>
  );
};

export default Hero;
