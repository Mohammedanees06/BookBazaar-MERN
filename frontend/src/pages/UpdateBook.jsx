import React, { useState } from 'react'

import axios from "axios";

import { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';





const UpdateBook = () => {
    const { id } = useParams();
    const navigate = useNavigate(); // Make sure this is declared at the top

    const headers = {
        Authorization: `Bearer ${localStorage.getItem("token")}`,
        id: localStorage.getItem("id"),
        bookid: id,
      };
    const [data, setData] = useState({
        url: '',
        title: '',
        author: '',
        price: '',
        description: '',
        language: '',
        category: ''
      });
      const [loading, setLoading] = useState(false);
      const [message, setMessage] = useState('');
    
    
      const handleChange = (e) => {
        const { name, value } = e.target;
        setData(prev => ({
          ...prev,
          [name]: value
        }));
      };
    
      const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setMessage('');
    
        try {

          const response = await axios.put(
            'http://localhost:3000/api/v1/updatebook',
            data,
            { headers  }
          );
    
          setMessage(response.data.message);
          navigate(`/viewbookdetails/${id}`);
          alert(response.data.message);
          
          setData({
            url: '',
            title: '',
            author: '',
            price: '',
            description: '',
            language: '',
            category: ''
          });
        } catch (error) {
          setMessage(error.response?.data?.message || 'Error adding book');
          alert(error.response?.data?.message || 'Error adding book');
        } finally {
          setLoading(false);
        }
      };
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
    
  return (
    <div className="min-h-screen bg-zinc-900 p-6">
      <div className="max-w-2xl mx-auto">
        <h1 className="text-3xl font-bold text-white mb-8 text-center">Update Book</h1>
        
        <form onSubmit={handleSubmit} className="bg-zinc-800 rounded-lg p-6 shadow-lg">
          <div className="space-y-4">
            {/* Title */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Book Title *
              </label>
              <input
                type="text"
                name="title"
                value={data.title}
                onChange={handleChange}
                required
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter book title"
              />
            </div>

            {/* Author */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Author *
              </label>
              <input
                type="text"
                name="author"
                value={data.author}
                onChange={handleChange}
                required
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter author name"
              />
            </div>

            {/* Price */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Price *
              </label>
              <input
                type="number"
                name="price"
                value={data.price}
                onChange={handleChange}
                required
                min="0"
                step="0.01"
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter price"
              />
            </div>

            {/* URL */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Book Cover URL *
              </label>
              <input
                type="url"
                name="url"
                value={data.url}
                onChange={handleChange}
                required
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="Enter book cover image URL"
              />
            </div>

            {/* Language */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Language *
              </label>
              <select
                name="language"
                value={data.language}
                onChange={handleChange}
                required
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select Language</option>
                <option value="English">English</option>
                <option value="Spanish">Spanish</option>
                <option value="French">French</option>
                <option value="German">German</option>
                <option value="Hindi">Hindi</option>
                <option value="Tamil">Tamil</option>
                <option value="Other">Other</option>
              </select>
            </div>

            {/* Category */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Category *
              </label>
              <select
                name="category"
                value={data.category}
                onChange={handleChange}
                required
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Select Category</option>
                <option value="Fiction">Fiction</option>
                <option value="Non-Fiction">Non-Fiction</option>
                <option value="Mystery">Mystery</option>
                <option value="Romance">Romance</option>
                <option value="Science Fiction">Science Fiction</option>
                <option value="Fantasy">Fantasy</option>
                <option value="Biography">Biography</option>
                <option value="History">History</option>
                <option value="Self-Help">Self-Help</option>
                <option value="Technology">Technology</option>
                <option value="Education">Education</option>
              </select>
            </div>

            {/* Description */}
            <div>
              <label className="block text-white text-sm font-medium mb-2">
                Description *
              </label>
              <textarea
                name="description"
                    value={data.description}
                onChange={handleChange}
                required
                rows="4"
                className="w-full px-3 py-2 bg-zinc-700 border border-zinc-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 resize-vertical"
                placeholder="Enter book description"
              />
            </div>
          </div>

          {/* Submit Button */}
          <div className="mt-6">
            <button
              type="submit"
              disabled={loading}
              className={`w-full py-3 px-4 rounded-md font-medium transition duration-200 ${
                loading
                  ? 'bg-gray-600 text-gray-300 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
              }`}
            >
              {loading ? 'Updating Book...' : 'Update Book'}
            </button>
          </div>

          {/* Message Display */}
          {message && (
            <div className={`mt-4 p-3 rounded-md ${
              message.includes('success') 
                ? 'bg-green-600 text-white' 
                : 'bg-red-600 text-white'
            }`}>
              {message}
            </div>
          )}
        </form>
      </div>
    </div>
  );
  
}

export default UpdateBook