// Import the createSlice function from Redux Toolkit
import { createSlice } from "@reduxjs/toolkit"; 

// Create a new slice of the Redux state for authentication
const authSlice = createSlice({
    // Name of the slice
    name: "auth",

    // Initial state of this slice
    initialState: {
        isLoggedIn: false,  // Tracks if the user is logged in
        role: "user"        // Default user role
    },

    // Reducers are functions that change the state
    
    reducers: {
       // This sets isLoggedIn to true (user is logged in)
       login(state) {
           state.isLoggedIn = true;
       },

       // This sets isLoggedIn to false (user is logged out)
       logout(state) {
           state.isLoggedIn = false;
       },

       // This sets the role to the new value passed in the action
       changeRole(state, action) {
           const role = action.payload; // Get the new role from the action
           state.role = role;
       },
    },
});

// Export the actions to use them in components (e.g., dispatch(authActions.login()))
export const authActions = authSlice.actions;

// Export the reducer to include it in the Redux store
export default authSlice.reducer;



// Creates authSlice – handles login status and user role using Redux Toolkit.

// Initial State:

// isLoggedIn: false → user is logged out by default.

// role: "user" → default role.

// Reducers:

// login → sets isLoggedIn to true.

// logout → sets isLoggedIn to false.

// changeRole → updates the role using action.payload.

// Exports:

// authActions → to trigger actions like login/logout/changeRole.

// authSlice.reducer → to use in Redux store.