import React, { useState, useEffect } from "react";
import axios from "axios";
import { FaTrash, FaCreditCard, FaSpinner } from "react-icons/fa";
import Loader from "../components/Loader/Loader";
import { useNavigate } from "react-router-dom";

const Cart = () => {
  const [cart, setCart] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [paymentLoading, setPaymentLoading] = useState(false);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [paymentMethod, setPaymentMethod] = useState('card');
  const [paymentDetails, setPaymentDetails] = useState({
    cardNumber: '',
    expiryDate: '',
    cvv: '',
    cardHolder: '',
    upiId: ''
  });
  const navigate = useNavigate();

  const headers = {
    Authorization: `Bearer ${localStorage.getItem("token")}`,
    id: localStorage.getItem("id"),
    order: cart,
  };

  useEffect(() => {
    const fetchCart = async () => {
      try {
        const response = await axios.get("http://localhost:3000/api/v1/getusercart", { headers });
        console.log(response.data.data);
        console.log(response.data.data.cart);
        setCart(response.data.data.cart || []);
      } catch (error) {
        console.error("Error fetching cart:", error);
      } finally {
        setLoading(false);
      }
    };
    fetchCart();
  }, []);

  useEffect(() => {
    let totalPrice = 0;
    cart.forEach((item) => {
      totalPrice += item.price;
    });
    setTotal(totalPrice);
  }, [cart]);

  const handleRemoveFromCart = async (id) => {
    try {
      const response = await axios.delete(`http://localhost:3000/api/v1/removefromcart/${id}`, { headers });
      alert(response.data.message);
      setCart((prev) => prev.filter((item) => item._id !== id));
    } catch (error) {
      console.error("Error removing from cart:", error);
    }
  };

  const handlePaymentInputChange = (e) => {
    const { name, value } = e.target;
    setPaymentDetails(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const simulatePaymentProcessing = () => {
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        // Simulate payment success/failure (90% success rate)
        if (Math.random() > 0.1) {
          resolve({
            success: true,
            transactionId: `TXN${Date.now()}${Math.floor(Math.random() * 1000)}`,
            paymentMethod: paymentMethod,
            amount: total
          });
        } else {
          reject(new Error('Payment failed. Please try again.'));
        }
      }, 3000); // 3 second delay to simulate processing
    });
  };

  const placeOrderCOD = async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      alert('User not authenticated.');
      return;
    }

    if (cart.length === 0) {
      alert('Your cart is empty.');
      return;
    }

    try {
      const orderData = {
        order: cart,
        paymentDetails: {
          paymentMethod: 'cod',
          status: 'pending',
          amount: total
        }
      };

      const response = await axios.post(
        'http://localhost:3000/api/v1/placeorder',
        orderData,
        { headers }
      );
      
      alert(response.data.message);
      console.log(response.data);
      navigate('/profile/orderhistory');
    } catch (error) {
      console.error('Error placing order:', error);
      alert('Failed to place order');
    }
  };

  const processPayment = async () => {
    setPaymentLoading(true);
    
    try {
      // Validate payment details
      if (paymentMethod === 'card') {
        if (!paymentDetails.cardNumber || !paymentDetails.expiryDate || 
            !paymentDetails.cvv || !paymentDetails.cardHolder) {
          alert('Please fill all card details');
          setPaymentLoading(false);
          return;
        }
        
        // Basic card number validation (should be 16 digits)
        if (paymentDetails.cardNumber.replace(/\s/g, '').length !== 16) {
          alert('Card number should be 16 digits');
          setPaymentLoading(false);
          return;
        }
      } else if (paymentMethod === 'upi') {
        if (!paymentDetails.upiId) {
          alert('Please enter UPI ID');
          setPaymentLoading(false);
          return;
        }
      }

      // Simulate payment processing
      const paymentResult = await simulatePaymentProcessing();
      
      if (paymentResult.success) {
        // Payment successful, now place the order
        await placeOrderAfterPayment(paymentResult);
      }
      
    } catch (error) {
      console.error('Payment error:', error);
      alert(error.message || 'Payment failed. Please try again.');
      setPaymentLoading(false);
    }
  };

  const placeOrderAfterPayment = async (paymentResult) => {
    const token = localStorage.getItem('token');
    if (!token) {
      alert('User not authenticated.');
      setPaymentLoading(false);
      return;
    }

    try {
      const orderData = {
        order: cart,
        paymentDetails: {
          transactionId: paymentResult.transactionId,
          paymentMethod: paymentResult.paymentMethod,
          amount: paymentResult.amount,
          status: 'completed'
        }
      };

      const response = await axios.post(
        'http://localhost:3000/api/v1/placeorder',
        orderData,
        { headers }
      );
      
      alert(`Order placed successfully! Transaction ID: ${paymentResult.transactionId}`);
      console.log(response.data);
      
      // Clear cart and close modal
      setCart([]);
      setShowPaymentModal(false);
      setPaymentDetails({
        cardNumber: '',
        expiryDate: '',
        cvv: '',
        cardHolder: '',
        upiId: ''
      });
      
      navigate('/profile/orderhistory');
    } catch (error) {
      console.error('Error placing order:', error);
      alert('Payment successful but order placement failed. Please contact support.');
    } finally {
      setPaymentLoading(false);
    }
  };

  const initiatePayment = () => {
    const token = localStorage.getItem('token');
    if (!token) {
      alert('User not authenticated.');
      return;
    }
    
    if (cart.length === 0) {
      alert('Your cart is empty.');
      return;
    }
    
    setShowPaymentModal(true);
  };

  const formatCardNumber = (value) => {
    // Remove all non-digit characters
    const v = value.replace(/\s+/g, '').replace(/[^0-9]/gi, '');
    // Add spaces every 4 digits
    const matches = v.match(/\d{4,16}/g);
    const match = matches && matches[0] || '';
    const parts = [];
    for (let i = 0, len = match.length; i < len; i += 4) {
      parts.push(match.substring(i, i + 4));
    }
    if (parts.length) {
      return parts.join(' ');
    } else {
      return v;
    }
  };

  const handleCardNumberChange = (e) => {
    const formatted = formatCardNumber(e.target.value);
    setPaymentDetails(prev => ({
      ...prev,
      cardNumber: formatted
    }));
  };

  if (loading) return <Loader />;

  return (
    <div className="bg-zinc-900 w-full min-h-screen flex flex-col items-center text-white p-4">
      {cart.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-[60vh]">
          <h1 className="text-2xl font-semibold mb-4 text-center">Empty Cart</h1>
          <img src="src/images/cart.png" alt="emptycart" className="h-[25vh] object-contain rounded-md" />
        </div>
      ) : (
        <>
          <h1 className="text-3xl font-semibold mb-6 text-center">Your Cart</h1>
          <div className="w-full max-w-5xl space-y-6">
            {cart.map((item, i) => (
              <div key={i} className="bg-zinc-800 p-4 rounded-lg shadow-md flex flex-col sm:flex-row items-center sm:items-start gap-4">
                <img src={item.url} alt={item.title} className="w-32 h-32 object-cover rounded-md" />
                <div className="flex-1 text-center sm:text-left">
                  <h2 className="text-xl font-bold">{item.title}</h2>
                  <p className="text-zinc-300 mt-2">{item.description?.slice(0, 100)}...</p>
                  <p className="text-yellow-400 mt-2 font-semibold text-lg">₹{item.price}</p>
                  <div className="mt-4 flex justify-center sm:justify-start">
                    <button
                      onClick={() => handleRemoveFromCart(item._id)}
                      className="bg-red-500 px-4 py-2 rounded-md flex items-center gap-2 hover:bg-red-600 transition"
                    >
                      <FaTrash />
                      Remove from cart
                    </button>
                  </div>
                </div>
              </div>
            ))}

            <div className="flex flex-col sm:flex-row justify-between items-center gap-4 p-4 bg-zinc-800 rounded-lg mt-6">
              <div className="text-center sm:text-left">
                <p className="text-2xl font-bold">Total: ₹{total}</p>
                <h2 className="text-gray-300">{cart.length} items in cart</h2>
              </div>
              <div className="flex flex-col sm:flex-row gap-3">
                <button
                  className="bg-blue-500 text-white px-6 py-3 rounded-md hover:bg-blue-600 transition flex items-center gap-2 text-lg font-semibold"
                  onClick={placeOrderCOD}
                >
                  Place Order (COD)
                </button>
                <button
                  className="bg-green-500 text-white px-6 py-3 rounded-md hover:bg-green-600 transition flex items-center gap-2 text-lg font-semibold"
                  onClick={initiatePayment}
                >
                  <FaCreditCard />
                  Pay Online
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Payment Modal */}
      {showPaymentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-zinc-800 rounded-lg p-6 w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-xl font-bold">Payment Details</h2>
              <button
                onClick={() => setShowPaymentModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
                disabled={paymentLoading}
              >
                ×
              </button>
            </div>

            <div className="mb-4">
              <p className="text-lg font-semibold mb-2">Order Total: ₹{total}</p>
            </div>

            {/* Payment Method Selection */}
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Payment Method</label>
              <div className="flex gap-4">
                <label className="flex items-center">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="card"
                    checked={paymentMethod === 'card'}
                    onChange={(e) => setPaymentMethod(e.target.value)}
                    className="mr-2"
                    disabled={paymentLoading}
                  />
                  Credit/Debit Card
                </label>
                <label className="flex items-center">
                  <input
                    type="radio"
                    name="paymentMethod"
                    value="upi"
                    checked={paymentMethod === 'upi'}
                    onChange={(e) => setPaymentMethod(e.target.value)}
                    className="mr-2"
                    disabled={paymentLoading}
                  />
                  UPI
                </label>
              </div>
            </div>

            {/* Card Payment Form */}
            {paymentMethod === 'card' && (
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Card Holder Name</label>
                  <input
                    type="text"
                    name="cardHolder"
                    value={paymentDetails.cardHolder}
                    onChange={handlePaymentInputChange}
                    className="w-full px-3 py-2 bg-zinc-700 rounded-md text-white"
                    placeholder="John Doe"
                    disabled={paymentLoading}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Card Number</label>
                  <input
                    type="text"
                    name="cardNumber"
                    value={paymentDetails.cardNumber}
                    onChange={handleCardNumberChange}
                    className="w-full px-3 py-2 bg-zinc-700 rounded-md text-white"
                    placeholder="1234 5678 9012 3456"
                    maxLength="19"
                    disabled={paymentLoading}
                  />
                </div>
                <div className="flex gap-4">
                  <div className="flex-1">
                    <label className="block text-sm font-medium mb-1">Expiry Date</label>
                    <input
                      type="text"
                      name="expiryDate"
                      value={paymentDetails.expiryDate}
                      onChange={handlePaymentInputChange}
                      className="w-full px-3 py-2 bg-zinc-700 rounded-md text-white"
                      placeholder="MM/YY"
                      maxLength="5"
                      disabled={paymentLoading}
                    />
                  </div>
                  <div className="flex-1">
                    <label className="block text-sm font-medium mb-1">CVV</label>
                    <input
                      type="text"
                      name="cvv"
                      value={paymentDetails.cvv}
                      onChange={handlePaymentInputChange}
                      className="w-full px-3 py-2 bg-zinc-700 rounded-md text-white"
                      placeholder="123"
                      maxLength="4"
                      disabled={paymentLoading}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* UPI Payment Form */}
            {paymentMethod === 'upi' && (
              <div>
                <label className="block text-sm font-medium mb-1">UPI ID</label>
                <input
                  type="text"
                  name="upiId"
                  value={paymentDetails.upiId}
                  onChange={handlePaymentInputChange}
                  className="w-full px-3 py-2 bg-zinc-700 rounded-md text-white"
                  placeholder="user@paytm"
                  disabled={paymentLoading}
                />
              </div>
            )}

            {/* Payment Button */}
            <div className="mt-6 flex gap-3">
              <button
                onClick={() => setShowPaymentModal(false)}
                className="flex-1 bg-gray-600 text-white py-2 px-4 rounded-md hover:bg-gray-700 transition"
                disabled={paymentLoading}
              >
                Cancel
              </button>
              <button
                onClick={processPayment}
                disabled={paymentLoading}
                className="flex-1 bg-green-500 text-white py-2 px-4 rounded-md hover:bg-green-600 transition flex items-center justify-center gap-2"
              >
                {paymentLoading ? (
                  <>
                    <FaSpinner className="animate-spin" />
                    Processing...
                  </>
                ) : (
                  <>
                    <FaCreditCard />
                    Pay ₹{total}
                  </>
                )}
              </button>
            </div>

            {/* Test Card Info */}
            <div className="mt-4 p-3 bg-zinc-700 rounded-md">
              <p className="text-xs text-gray-300 mb-2">Test Card Details:</p>
              <p className="text-xs text-gray-400">Card: 4111 1111 1111 1111</p>
              <p className="text-xs text-gray-400">Expiry: 12/25 | CVV: 123</p>
              <p className="text-xs text-gray-400">UPI: test@paytm</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Cart;