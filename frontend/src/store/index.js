import { configureStore } from "@reduxjs/toolkit";
import authReducer from "./auth";

const store = configureStore({
    reducer: { // inital and final state for user loggedin and out
        auth: authReducer,
        
    },
});

export default store;