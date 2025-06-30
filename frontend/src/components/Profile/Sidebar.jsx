import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import { authActions } from "../../store/auth";
import { FaUserCircle } from "react-icons/fa";
import { useSelector } from "react-redux";
import axios from "axios";
import { useState, useEffect } from "react";

const Sidebar = () => {
  // const Sidebar = ({ data }) => {

  const dispatch = useDispatch();
  const navigate = useNavigate();
  const role = useSelector((state) => state.auth.role);
  const [userData, setUserData] = useState({});

  useEffect(() => {
    const fetchUserInfo = async () => {
      try {
        const token = localStorage.getItem("token");
        const id = localStorage.getItem("id");

        const response = await axios.get(
          `http://localhost:3000/api/v1/getuserinfo`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
              id: id,
            },
          }
        );
        setUserData(response.data.data);
        console.log(response.data.data);
      } catch (error) {
        console.error("Failed to fetch user info", error);
      }
    };

    fetchUserInfo();
  }, []);

  const handleLogout = () => {
    localStorage.clear(); // remove token, id, etc.
    dispatch(authActions.logout());
    dispatch(authActions.changeRole("user"));
    navigate("/");
  };

  return (
    <div className="bg-zinc-800 mt-7 md:h-[75vh] h-auto md:w-80 w-full rounded-lg p-6 shadow-lg flex flex-col justify-between items-center overflow-y-auto max-h-[85vh] md:sticky md:top-5">
      {/* User Data Section */}
      <div className="flex flex-col items-center space-y-6">
        {userData.avatar ? (
          <img
            src={userData.avatar}
            alt="User Avatar"
            className="w-20 h-20 rounded-full object-cover border-4 border-yellow-400 mb-4"
          />
        ) : (
          <FaUserCircle className="text-yellow-400 w-20 h-20 text-6xl mb-4" />
        )}

        <div className="text-center">
          <h1 className="text-white text-2xl font-semibold">
            {userData.username}
          </h1>
          <p className="text-zinc-400 text-sm">{userData.email}</p>
        </div>
      </div>

      {/* Navigation Links Section */}
      {role === "user" && (
        <div className="w-full flex flex-col items-center space-y-4 flex-1 mt-10">
          <Link
            to="/profile"
            className="text-white text-base w-full text-center py-2 rounded-md hover:bg-zinc-700 hover:text-blue-400 transition duration-200"
          >
            ⭐ Favorites
          </Link>
          <Link
            to="/profile/orderhistory"
            className="text-white text-base w-full text-center py-2 rounded-md hover:bg-zinc-700 hover:text-blue-400 transition duration-200"
          >
            📦 Order History
          </Link>
          <Link
            to="/profile/settings"
            className="text-white text-base w-full text-center py-2 rounded-md hover:bg-zinc-700 hover:text-blue-400 transition duration-200"
          >
            ⚙️ Settings
          </Link>
        </div>
      )}
      {role === "admin" && (
        <div className="w-full flex flex-col items-center space-y-4 flex-1 mt-10">
          <Link
            to="/profile"
            className="text-white text-base w-full text-center py-2 rounded-md hover:bg-zinc-700 hover:text-blue-400 transition duration-200"
          >
             📦 All Orders
          </Link>
          <Link
            to="/profile/addbook"
            className="text-white text-base w-full text-center py-2 rounded-md hover:bg-zinc-700 hover:text-blue-400 transition duration-200"
          >
              📚 Add Book
          </Link>
        </div>
      )}

      {/* Logout Button Section */}
      <div className="w-full flex flex-col items-center mt-6 md:mt-0">
        <button
          onClick={handleLogout}
          className="text-red-400 text-base w-full text-center py-2 rounded-md hover:bg-red-600 hover:text-white transition duration-200"
        >
          🚪 Logout
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
