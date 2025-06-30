import React from "react";
import { useState, useEffect } from "react";
import axios from "axios";
import Loader from "../Loader/Loader";

const Settings = () => {
  const [value, setValue] = useState({ address: "" });
  const [profileData, setProfileData] = useState({});
  const headers = {
    id: localStorage.getItem("id"),
    Authorization: `Bearer ${localStorage.getItem("token")}`,
  };
  const change = (e) => {
    const { name, value: val } = e.target;
    setValue((prev) => ({ ...prev, [name]: val }));
  };
  const updateAddress = async () => {
    const response = await axios.put(
      "http://localhost:3000/api/v1/updateaddress",
      value,
      { headers }
    );
    alert(response.data.message);

    
    
  };
  useEffect(() => {
    const fetchUser = async () => {
      const response = await axios.get(
        "http://localhost:3000/api/v1/getuserinfo",
        { headers }
      );
      setValue({ address: response.data.data.address });
      setProfileData(response.data.data);
      console.log(response);
      console.log(response.data.data.address);
    };
    fetchUser();
  }, []);

  return (
    
    <div className="bg-zinc-900 min-h-screen w-full p-6 flex justify-center items-start text-white">
      <div className="w-full max-w-3xl bg-zinc-800 p-8 rounded-xl shadow-lg">
        <h1 className="text-3xl font-bold mb-8 text-center border-b border-zinc-700 pb-4">
          User Settings
        </h1>

        <div className="space-y-6">
          <div>
            <h2 className="text-lg font-semibold text-zinc-200">Username</h2>
            <p className="text-zinc-400">
              {profileData.username || "Not provided"}
            </p>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-zinc-200">Email</h2>
            <p className="text-zinc-400">
              {profileData.email || "Not provided"}
            </p>
          </div>
          <div>
            <h2 className="text-lg font-semibold text-zinc-200">Address</h2>
            <textarea
              className="text-zinc-400 bg-zinc-700 p-2 rounded-md w-full min-h-[100px]"
              onChange={change}
              name="address"
              value={value.address}
            />
          </div>
          <div className="flex justify-center items-center">
            <button
              onClick={updateAddress}
              className="bg-yellow-500 hover:bg-yellow-700 text-white px-4 py-2 rounded-md text-sm transition-colors"
            >
              Update Address
            </button>
          </div>

          <div>
            <h2 className="text-lg font-semibold text-zinc-200">Phone</h2>
            <p className="text-zinc-400">
              {profileData.phone || "Not provided"}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
