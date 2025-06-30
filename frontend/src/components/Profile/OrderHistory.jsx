import React, { useEffect, useState } from "react";
import axios from "axios";
import Loader from "../Loader/Loader";
import { Link } from 'react-router-dom';
// adjust path


const OrderHistory = () => {
  const [ordersHistory, setOrdersHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const headers = {
    id: localStorage.getItem("id"),
    Authorization: `Bearer ${localStorage.getItem("token")}`,
  };

  useEffect(() => {
    const fetchOrderHistory = async () => {
      try {
        setError(null);
        const response = await axios.get("http://localhost:3000/api/v1/getordershistory", { headers });
        
        console.log("Full response:", response);
        console.log("Orders data:", response.data.data);
        console.log("Total orders received:", response.data.data?.length);
        
        if (response.data.status === "success") {
          const orders = response.data.data || [];
          setOrdersHistory(orders);
          
          // Debug: Log detailed order information
          if (orders.length > 0) {
            console.log("First order structure:", orders[0]);
            console.log("Book data:", orders[0].books || orders[0].book);
            
            // Log all order dates for debugging
            orders.forEach((order, index) => {
              console.log(`Order ${index + 1} date:`, order.createdAt, "- Parsed:", new Date(order.createdAt));
            });
            
            // Check date filtering
            const today = new Date();
            const todaysOrders = orders.filter(order => {
              const orderDate = new Date(order.createdAt);
              return orderDate.toDateString() === today.toDateString();
            });
            console.log("Today's orders:", todaysOrders.length);
            
            const yesterday = new Date();
            yesterday.setDate(yesterday.getDate() - 1);
            const yesterdaysOrders = orders.filter(order => {
              const orderDate = new Date(order.createdAt);
              return orderDate.toDateString() === yesterday.toDateString();
            });
            console.log("Yesterday's orders:", yesterdaysOrders.length);
          }
        } else {
          setError("Failed to fetch order history");
        }
      } catch (error) {
        console.error("Error fetching order history:", error);
        setError(error.response?.data?.message || "Failed to fetch order history");
      } finally {
        setLoading(false);
      }
    };

    fetchOrderHistory();
  }, []);

  if (loading) return <Loader />;

  if (error) {
    return (
      <div className="bg-zinc-900 w-full min-h-screen flex flex-col items-center justify-center text-white p-4">
        <h1 className="text-2xl font-semibold mb-4 text-red-400">Error</h1>
        <p className="text-zinc-300 text-center">{error}</p>
        <button 
          onClick={() => window.location.reload()} 
          className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="bg-zinc-900  w-full min-h-screen flex flex-col items-center text-white p-4">
      <h1 className="text-3xl font-semibold mb-6 text-center">Order History</h1>

      {ordersHistory.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-[60vh]">
          <h1 className="text-2xl font-semibold mb-4 text-center">No Orders Found</h1>
          <img 
            src="/images/empty-orders.png" 
            alt="no-orders" 
            className="h-[25vh] object-contain rounded-md"
            onError={(e) => {
              e.target.style.display = 'none';
            }}
          />
        </div>
      ) : (
        <div className="w-full max-w-5xl">
          {/* Summary Section */}
          <div className="mb-6 bg-zinc-800 p-4 rounded-lg">
            <h2 className="text-xl font-semibold mb-2">Order Summary</h2>
            <p className="text-zinc-300">Total Orders: {ordersHistory.length}</p>
           
          </div>

          {/* Orders List */}
          <div className="space-y-6">
            {ordersHistory.map((order, i) => {
              // Handle both 'books' (array) and 'book' (single object) cases
              const bookData = order.books?.[0] || order.books || order.book;
              const orderDate = new Date(order.createdAt);
              const isToday = orderDate.toDateString() === new Date().toDateString();
              const yesterday = new Date();
              yesterday.setDate(yesterday.getDate() - 1);
              const isYesterday = orderDate.toDateString() === yesterday.toDateString();

              
              return (
                <div 
                  key={order._id || i} 
                  className={`bg-zinc-800 p-4 rounded-lg shadow-md flex flex-col sm:flex-row items-center sm:items-start gap-4 ${
                    isToday ? 'border-l-4 border-green-500' : isYesterday ? 'border-l-4 border-yellow-500' : ''
                  }`}
                >
                  <img
                    src={bookData?.url || "/images/default-book.png"}
                    alt={bookData?.title || "Book"}
                    className="w-32 h-32 object-cover rounded-md"
                    onError={(e) => {
                      e.target.src = "/images/default-book.png";
                    }}
                  />

                  <div className="flex-1 text-center sm:text-left">
                    <div className="flex items-center gap-2 mb-2">
                      <h2 className="text-xl font-bold">
                        {bookData?.title || "Unknown Title"}
                      </h2>
                      
                      {isToday && <span className="bg-green-600 text-xs px-2 py-1 rounded">TODAY</span>}
                      {isYesterday && <span className="bg-yellow-600 text-xs px-2 py-1 rounded">YESTERDAY</span>}
                    </div>
                    <p className="text-zinc-300 mt-2">
                      {bookData?.description 
                        ? `${bookData.description.slice(0, 100)}...` 
                        : "No description available"}
                    </p>
                    <p className="text-yellow-400 mt-2 font-semibold text-lg">
                      ₹{bookData?.price || "N/A"}
                    </p>
                    <p className="text-zinc-400 mt-1 text-sm">
                      Ordered on: {order.createdAt 
                        ? new Date(order.createdAt).toLocaleString() 
                        : "Date not available"}
                    </p>
                    
                    <p className="text-zinc-300 mt-1 text-sm">
                      Order ID: {order._id || "N/A"}
                    </p>
                    <p>
                      {order.status==="ordered" ? (
                        <h1 className="text-green-900">{order.status}</h1>
                      ) : order.status==="cancelled" ? (
                        <h1 className="text-red-900">{order.status}</h1>
                      ) : (
                        <h1 className="text-yellow-500">{order.status}</h1>
                      )}
                    </p>
                    <p className="text-zinc-200 mt-1  text-sm">
                      Mode of Payment: COD
                    </p>
                    <Link to={`/viewbookdetails/${bookData?._id}`}>
                      <button className="bg-blue-600 hover:bg-blue-700 mt-3 text-white px-4 py-2 rounded-md text-sm transition-colors">
                        View Book Details
                      </button>
                     
                    </Link>
                    
                    
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

export default OrderHistory;