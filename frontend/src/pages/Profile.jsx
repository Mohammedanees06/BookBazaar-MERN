import React, { useEffect, useState } from "react";
import Sidebar from "../components/Profile/Sidebar";
import { Outlet } from "react-router-dom";
import axios from "axios";
import Loader from "../components/Loader/Loader";


const Profile = () => {
  const [profile, setProfile] = useState(null);

  const headers = {
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    id: localStorage.getItem("id"),
  };

  useEffect(() => {
    const fetch = async () => {
      try {
        const response = await axios.get("http://localhost:3000/api/v1/getuserinfo", { headers });
        setProfile(response.data);
      } catch (error) {
        console.error("Failed to fetch user info", error);
      }
    };
    fetch();
  }, []);

  if (!profile) {
    return (
      <div className="flex justify-center items-center h-screen bg-zinc-900">
        <Loader />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-zinc-900 text-white flex flex-col md:flex-row gap-4 md:gap-0">
      {/* Sidebar */}
      <aside className="md:w-1/4 p-6 border-r border-zinc-800 min-h-screen">
        <Sidebar data={profile} />
      </aside>

      {/* Main Content */}
      <main className="md:w-3/4 p-6 min-h-screen">
        <Outlet />
      </main>
    </div>
  );
};

export default Profile;
