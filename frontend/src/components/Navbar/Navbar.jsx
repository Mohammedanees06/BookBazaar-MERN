import React, { useState } from "react"; 
import { Link } from 'react-router-dom';
import logo from '../../images/logo.png';
import { useSelector } from "react-redux";

const Navbar = () => {
  const [menuOpen, setMenuOpen] = useState(false);
  const isLoggedIn = useSelector((state) => state.auth.isLoggedIn);
  const role = useSelector((state) => state.auth.role);

  const allLinks = [
    { title: "Home", link: "/" },
    { title: "All Books", link: "/all-books" },
    { title: "Cart", link: "/cart" },
    { title: "Profile", link: "/profile" },
    { title: "Admin Profile", link: "/profile" },
  ];
  
  function getLinks(isLoggedIn, role) {
    if (!isLoggedIn) {
      return allLinks.slice(0, 2);
    }
    if (role === "admin") {
      return [allLinks[0], allLinks[1], allLinks[4]];
    }
    return allLinks.slice(0, 4);
  }
  
  // Usage
  const links = getLinks(isLoggedIn, role);
  
  return (
    <nav className="bg-zinc-900 text-white px-6 py-3 shadow-md border-b border-zinc-700">
      {/* Enhancement: Max width for responsive centering */}
      <div className="max-w-7xl mx-auto">

        <div className="flex items-center justify-between mt-1">
          {/* Logo & Title */}
          <div className="flex items-center">
            <img
              src={logo}
              alt="Book Icon"
              className="w-8 h-8 me-3" // Enhancement: Better scaling
            />
            <Link to="/">
              <h1 className="text-2xl font-bold tracking-wide">BookBazaar</h1> {/* Enhancement: Font bold and spacing */}
            </Link>
          </div>

          {/* Hamburger (Mobile) */}
          <div className="lg:hidden">
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="focus:outline-none p-2 rounded hover:bg-zinc-800 transition" // Enhancement
            >
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                {menuOpen ? (
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M6 18L18 6M6 6l12 12"
                  />
                ) : (
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                )}
              </svg>
            </button>
          </div>

          {/* Nav Links (Large Screen) */}
          <div className="hidden lg:flex items-center gap-6">
            {links.map((link) => (
              <a
                key={link.title}
                href={link.link}
                className="hover:text-blue-400 transition duration-200 ease-in-out" // Enhancement
              >
                {link.title}
              </a>
            ))}
            {isLoggedIn === false && (
              <div className="flex gap-4 mt-2">
                <Link to="/Login">
                  <button className="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-1.5 px-4 rounded-lg shadow transition duration-200">
                    Login
                  </button>
                </Link>
                <Link to="/SignUp">
                  <button className="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-1.5 px-4 rounded-lg shadow transition duration-200">
                    Signup
                  </button>
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Mobile Menu */}
        {menuOpen && (
          <div className="lg:hidden mt-4 flex flex-col gap-4 px-2"> {/* Enhancement: Added padding */}
            {links.map((link) => (
              <a
                key={link.title}
                href={link.link}
                className="hover:text-blue-400 transition duration-200 ease-in-out" // Enhancement
              >
                {link.title}
              </a>
            ))}
            {isLoggedIn === false && (
              <div className="flex gap-4 mt-2">
                <Link to="/Login">
                  <button className="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-1.5 px-4 rounded-lg shadow transition duration-200">
                    Login
                  </button>
                </Link>
                <Link to="/SignUp">
                  <button className="bg-blue-500 hover:bg-blue-600 text-white font-semibold py-1.5 px-4 rounded-lg shadow transition duration-200">
                    Signup
                  </button>
                </Link>
              </div>
            )}
          </div>
        )}
        
      </div>
    </nav>
  );
};

export default Navbar;
