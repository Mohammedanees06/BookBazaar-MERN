import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";

const SignUp = () => {
  const [Values, setValues] = useState({
    username: "", email: "", password: "", address: ""
  });
  const [error, setError] = useState("");
  const navigate = useNavigate();


  const Change = (e) => {
    const {name,value} = e.target;
    setValues({...Values,[name]:value});
  }
  const Submit = async (e) => {
    e.preventDefault();
   
    try{
        if (
            Values.username.length < 4 || Values.username.length > 15 ||
            Values.password.length < 8 || Values.password.length > 20 ||
            Values.email.length < 8|| Values.email.length > 30 ||
            Values.address.length < 6 || Values.address.length > 50
          ) {
            alert("Please enter valid details:\n- Username (4-15 chars)\n- Password (8-20 chars)\n- Email (10-30 chars)\n- Address (10-50 chars)");
            return;
          }
          
          else{
            
           const response = await axios.post("http://localhost:3000/api/v1/signup", Values);
           console.log(response);
           alert(response.data.message);
           navigate("/Login");
          }
   
    }
    catch(err){
      setError(err.response?.data?.message || "Signup failed");
      alert(err.response?.data?.message || "Signup failed");
    }
  }

  return (
    <div className="min-h-screen bg-zinc-900 flex items-center justify-center px-4">
      <div className="bg-zinc-800 p-8 rounded-lg shadow-md w-full max-w-md text-white">
        <h2 className="text-3xl font-bold mb-6 text-yellow-400 text-center">Sign Up</h2>
        {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
        <form onSubmit={Submit} className="space-y-4">
          <div>
            <label className="block text-sm mb-1">Username</label>
            <input
              type="text"
              name="username"
              required
              value={Values.username}
              onChange={Change}
              className="w-full p-2 rounded bg-zinc-700 border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-400"
            />
          </div>
          <div>
            <label className="block text-sm mb-1">Email</label>
            <input
              type="email"
              name="email"
              required
              value={Values.email}
              onChange={Change}
              className="w-full p-2 rounded bg-zinc-700 border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-400"
            />
          </div>
          <div>
            <label className="block text-sm mb-1">Password</label>
            <input
              type="password"
              name="password"
              required
              value={Values.password}
              onChange={Change}
              className="w-full p-2 rounded bg-zinc-700 border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-400"
            />
          </div>
          <div>
            <label className="block text-sm mb-1">Address</label>
            <input
              type="text"
              name="address"
              required
              value={Values.address}
              onChange={Change}
              className="w-full p-2 rounded bg-zinc-700 border border-zinc-600 focus:outline-none focus:ring-2 focus:ring-yellow-400"
            />
          </div>
          <button
            type="submit"
            onClick={Submit}
            className="w-full py-2 mt-2 bg-yellow-400 text-black font-semibold rounded hover:bg-yellow-500 transition"
          >
            Sign Up
          </button>
        </form>
        <p className="mt-6 text-sm text-center text-gray-300">
          Already have an account?{" "}
          <Link to="/Login" className="text-yellow-400 hover:underline">Login</Link>
        </p>
      </div>
    </div>
  );
};

export default SignUp;
