import React, { useEffect, useState } from "react";
import axios from "axios";
import Loader from "../components/Loader/Loader";
import { Link } from "react-router-dom";
import UserData from "./UserData"; // ✅ Adjust this path if needed

const AllOrders = () => {
  const headers = {
    id: localStorage.getItem("id"),
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    "Content-Type": "application/json",
  };

  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedStatus, setSelectedStatus] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [userDiv, setUserDiv] = useState("hidden");
  const [userDivData, setUserDivData] = useState();

  useEffect(() => {
    const fetchOrders = async () => {
      try {
        const response = await axios.get("http://localhost:3000/api/v1/getallorders", { headers });
        const ordersData = response.data.data;

        const ordersWithUsers = await Promise.all(
          ordersData.map(async (order) => {
            const userId = order.user?._id || order.user;
            try {
              const userRes = await axios.get("http://localhost:3000/api/v1/getuserinfo", {
                headers: { ...headers, id: userId },
              });
              return { ...order, userInfo: userRes.data.data };
            } catch {
              return { ...order, userInfo: null };
            }
          })
        );

        setOrders(ordersWithUsers);
      } catch (err) {
        console.error("Error fetching orders:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchOrders();
  }, []);

  const handleStatusChange = async (index) => {
    const order = orders[index];
    if (!selectedStatus) {
      alert("Please select a status before updating.");
      return;
    }

    try {
      await axios.put(
        `http://localhost:3000/api/v1/updateorderstatus/${order._id}`,
        { status: selectedStatus },
        { headers }
      );

      const updatedOrder = { ...order, status: selectedStatus };
      const updatedOrders = [...orders];
      updatedOrders[index] = updatedOrder;
      setOrders(updatedOrders);
      setSelectedIndex(-1);
      setSelectedStatus("");

      alert("Order status updated successfully!");
    } catch (error) {
      console.error("Error updating order:", error);
      alert("Failed to update order status.");
    }
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <Loader />
      </div>
    );
  }

  return (
    <div className="p-4 bg-zinc-800 rounded-lg shadow-md">
      <h2 className="text-2xl font-bold text-white mb-6">All Orders</h2>

      <div className="grid grid-cols-7 gap-4 bg-zinc-700 text-white font-semibold p-3 rounded-lg shadow-md text-center">
        <div>#</div>
        <div>User</div>
        <div>Books</div>
        <div>Description</div>
        <div>Status</div>
        <div>Payment</div>
        <div>Update</div>
      </div>

      {orders.map((order, index) => (
        <div
          key={order._id}
          className="grid grid-cols-7 gap-4 bg-zinc-800 text-white p-3 rounded-lg shadow-sm items-center text-center mt-2"
        >
          <div>{index + 1}</div>

          <div>
            <button
              onClick={() => {
                setUserDiv("fixed");
                setUserDivData(order.userInfo);
              }}
              className="bg-indigo-500 hover:bg-indigo-600 text-white px-3 py-1 rounded text-sm"
            >
              View User Info
            </button>
          </div>

          <div>
            {Array.isArray(order.books) && order.books.length > 0 ? (
              <Link
                to={`/viewbookdetails/${order.books[0]?._id || ""}`}
                className="text-blue-500 hover:text-blue-600"
              >
                {order.books.map((book) => book?.title || "N/A").join(", ")}
              </Link>
            ) : (
              <span>No books</span>
            )}
          </div>

          <div>
            ₹{order.books?.reduce((acc, book) => acc + (book?.price || 0), 0)}
          </div>

          <div>
            <button
              className={`px-4 py-2 rounded-md ${
                order.status === "order placed"
                  ? "bg-green-500"
                  : order.status === "cancelled"
                  ? "bg-red-500"
                  : "bg-blue-500"
              }`}
              onClick={() => {
                setSelectedIndex(index);
              }}
            >
              {order.status}
            </button>
          </div>

          <div>{order.paymentMethod || "COD"}</div>

          <div>
            {selectedIndex === index && (
              <div className="flex flex-col gap-2 items-center justify-center w-full">
                <select
                  className="bg-zinc-700 text-white px-3 py-1 rounded w-full max-w-xs"
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                >
                  <option value="">Select</option>
                  {[
                    "order placed",
                    "processing",
                    "shipped",
                    "out for delivery",
                    "delivered",
                    "cancelled",
                  ].map((status, i) => (
                    <option key={i} value={status}>
                      {status}
                    </option>
                  ))}
                </select>
                <button
                  onClick={() => handleStatusChange(index)}
                  className="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-white text-sm w-full max-w-xs"
                >
                  Update
                </button>
              </div>
            )}
          </div>
        </div>
      ))}

      {userDivData && (
        <UserData
          userDivData={userDivData}
          userDiv={userDiv}
          setUserDiv={setUserDiv}
        />
      )}
    </div>
  );
};

export default AllOrders;
