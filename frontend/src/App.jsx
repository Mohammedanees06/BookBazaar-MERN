import "./App.css";
import Footer from "./components/Footer/Footer";
import Navbar from "./components/Navbar/Navbar";
import "./index.css";
import AllBooks from "./pages/AllBooks";
import Home from "./pages/Home";
import { Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import SignUp from "./pages/SignUp";
import Cart from "./pages/Cart";
import Profile from "./pages/Profile";
import ViewBookDetails from "./components/VIewBookDetails/ViewBookDetails";
import { useSelector, useDispatch } from "react-redux"; // combined
import { authActions } from "./store/auth";
import { useEffect } from "react";
import Favourites from "./components/Profile/Faviourites";
import OrderHistory from "./components/Profile/OrderHistory";
import Settings from "./components/Profile/Settings";
import AllOrders from "./pages/AllOrders";
import AddBook from "./pages/AddBook";
import UpdateBook from "./pages/UpdateBook";

function App() {
  const dispatch = useDispatch(); // ✅ initialize dispatch
  const role = useSelector((state) => state.auth.role);

  useEffect(() => {
    if (
      localStorage.getItem("token") &&
      localStorage.getItem("role") &&
      localStorage.getItem("id")
    ) {
      dispatch(authActions.login());
      dispatch(authActions.changeRole(localStorage.getItem("role")));
    }
  }, [dispatch]);

  return (
    <div>
      <Navbar />
      <Routes>
        <Route exact path="/" element={<Home />} />
        <Route path="/all-books" element={<AllBooks />} />
        <Route path="/cart" element={<Cart />} />
        <Route path="/profile" element={<Profile />}>
          {role === "user" ? (
            <Route index element={<Favourites />} />
          ) : (
            <Route index element={<AllOrders />} />
          )}
          {role=== "admin" && (
            <Route path="/profile/addbook" element={<AddBook />} />
          )}
          <Route path="/profile/orderhistory" element={<OrderHistory />} />
          <Route path="/profile/settings" element={<Settings />} />
        </Route>

        <Route path="/Login" element={<Login />} />
        <Route path="/SignUp" element={<SignUp />} />
        <Route path="/updateBook/:id" element={<UpdateBook />} />
        <Route path="/viewbookdetails/:id" element={<ViewBookDetails />} />
      </Routes>
      <Footer />
    </div>
  );
}

export default App;
