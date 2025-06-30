import React, { useState, useEffect } from "react";
import axios from "axios";
import BookCard from "../components/BookCard/BookCard";
import Loader from "../components/Loader/Loader";

const AllBooks = () => {
  const [Data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  const [selectedCategory, setSelectedCategory] = useState("All");
  const [selectedLanguage, setSelectedLanguage] = useState("All");
  const [selectedCostRange, setSelectedCostRange] = useState("All");
  const [searchTerm, setSearchTerm] = useState("");

  const [categories, setCategories] = useState(["All"]);
  const [languages, setLanguages] = useState(["All"]);

  const costRanges = [
    "All",
    "Under ₹200",
    "₹200 - ₹499",
    "₹500 and above"
  ];

  useEffect(() => {
    const fetch = async () => {
      try {
        const response = await axios.get("http://localhost:3000/api/v1/getallbooks");
        const books = response.data?.data?.books || [];
        setData(books);

        const uniqueCategories = ["All", ...new Set(books.map((book) => book.category))];
        const uniqueLanguages = ["All", ...new Set(books.map((book) => book.language))];

        setCategories(uniqueCategories);
        setLanguages(uniqueLanguages);
      } catch (error) {
        console.error("Failed to fetch books:", error);
      } finally {
        setLoading(false);
      }
    };
    fetch();
  }, []);

  const filteredBooks = Data.filter((book) => {
    const matchesCategory = selectedCategory === "All" || book.category === selectedCategory;
    const matchesLanguage = selectedLanguage === "All" || book.language === selectedLanguage;
    const matchesSearch =
      book.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      book.author.toLowerCase().includes(searchTerm.toLowerCase());

    const price = book.price || 0;
    let matchesCost = true;
    if (selectedCostRange === "Under ₹200") matchesCost = price < 200;
    else if (selectedCostRange === "₹200 - ₹499") matchesCost = price >= 200 && price <= 499;
    else if (selectedCostRange === "₹500 and above") matchesCost = price >= 500;

    return matchesCategory && matchesLanguage && matchesSearch && matchesCost;
  });

  return (
    <div className="bg-zinc-900 text-white px-4 sm:px-8 md:px-10 py-8 min-h-screen">
      <h1 className="text-3xl font-bold text-yellow-500 mb-6">All Books</h1>

      {/* Filters Section */}
      <div className="mb-8 bg-zinc-800 p-4 rounded-xl shadow-lg flex flex-col md:flex-row flex-wrap gap-4 items-center justify-between">
        {/* Category Filter */}
        <div className="flex flex-col">
          <label className="text-sm text-gray-300 mb-1 font-medium">Category</label>
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-zinc-700 text-white px-4 py-2 rounded-md border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-500"
          >
            {categories.map((cat, idx) => (
              <option key={idx} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>

        {/* Language Filter */}
        <div className="flex flex-col">
          <label className="text-sm text-gray-300 mb-1 font-medium">Language</label>
          <select
            value={selectedLanguage}
            onChange={(e) => setSelectedLanguage(e.target.value)}
            className="bg-zinc-700 text-white px-4 py-2 rounded-md border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-500"
          >
            {languages.map((lang, idx) => (
              <option key={idx} value={lang}>
                {lang}
              </option>
            ))}
          </select>
        </div>

        {/* Cost Filter */}
        <div className="flex flex-col">
          <label className="text-sm text-gray-300 mb-1 font-medium">Cost</label>
          <select
            value={selectedCostRange}
            onChange={(e) => setSelectedCostRange(e.target.value)}
            className="bg-zinc-700 text-white px-4 py-2 rounded-md border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-500"
          >
            {costRanges.map((range, idx) => (
              <option key={idx} value={range}>
                {range}
              </option>
            ))}
          </select>
        </div>

        {/* Search Filter */}
        <div className="flex flex-col w-full md:w-64">
          <label className="text-sm text-gray-300 mb-1 font-medium">Search</label>
          <input
            type="text"
            placeholder="Search by title or author"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="bg-zinc-700 text-white px-4 py-2 rounded-md border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-500"
          />
        </div>
      </div>

      {/* Loader / Results */}
      {loading ? (
        <div className="flex justify-center items-center h-66">
          <Loader />
        </div>
      ) : filteredBooks.length === 0 ? (
        <p className="text-center text-gray-400">No books found.</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
          {filteredBooks.map((item, i) => (
            <BookCard key={i} data={item} />
          ))}
        </div>
      )}
    </div>
  );
};

export default AllBooks;
