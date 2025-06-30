import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import {authActions} from "../store/auth";
import { useDispatch } from "react-redux";

const Login = () =>  {
    const [Values, setValues] = useState({
      username: "",  password: "",
    });
    const [error, setError] = useState("");
    const navigate = useNavigate();
    const dispatch = useDispatch();
  
    const Change = (e) => {
      const {name,value} = e.target;
      setValues({...Values,[name]:value});
    }
    const Submit = async (e) => {
      e.preventDefault();
     
      try{
          if (
              Values.username.length  === "" ||  Values.password.length === ""  ) 
              {
              alert("Please enter valid details:");
              return;
            }
            
            else{
              
             const response = await axios.post("http://localhost:3000/api/v1/signin", Values);
            
             dispatch(authActions.login());
             dispatch(authActions.changeRole(response.data.role));
             localStorage.setItem("token", response.data.token);
             localStorage.setItem("role", response.data.role);
             localStorage.setItem("id", response.data.id);

             console.log(response.data.role);
             alert("Login successful");
            //  navigate("/profile");
            window.location.href = "/profile";

             
           
            }
     
      }
      catch(err){
        setError(err.response?.data?.message || "Signin failed");
        alert(err.response?.data?.message || "Signin failed");
      }
    }

  return (
    <div className="min-h-screen bg-zinc-900 flex items-center justify-center px-4">
      <div className="bg-zinc-800 p-8 rounded-lg shadow-md w-full max-w-md text-white">
        <h2 className="text-3xl font-bold mb-6 text-yellow-400 text-center">Login</h2>
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
          <button
            type="submit"
            onClick={Submit}
            className="w-full py-2 mt-2 bg-yellow-400 text-black font-semibold rounded hover:bg-yellow-500 transition"
          >
            Login
          </button>
        </form>
        <p className="mt-6 text-sm text-center text-gray-300">
          Don't have an account?{" "}
          <Link to="/SignUp" className="text-yellow-400 hover:underline">Sign up</Link>
        </p>
      </div>
    </div>
  );
};

export default Login;
