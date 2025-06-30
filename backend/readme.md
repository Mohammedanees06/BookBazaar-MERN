
# 📦 Bookstore Backend – Project Structure & File Connections

This project is the backend for an online bookstore, built using Node.js, Express.js, and MongoDB. It handles user authentication, book management, cart, orders, and favourites.

---

## 📁 Folder & File Structure

```
backend
├── conn/
├── models/
│   ├── book.js
│   ├── order.js
│   ├── user.js
├── node_modules/
├── routes/
│   ├── book.js
│   ├── cart.js
│   ├── favourite.js
│   ├── order.js
│   ├── user.js
│   ├── userAuth.js
├── .env
├── app.js
├── package-lock.json
├── package.json
```

---

## 🔗 How Everything Is Connected

### 📄 `app.js` – Main Entry Point

* This is the heart of your app.
* It connects to the database, sets up Express, loads routes, and starts the server.
* Imports route files from the `routes` folder.
* Example:

  ```js
  const userRoutes = require('./routes/user');
  app.use('/api/user', userRoutes);
  ```

---

### 📁 `conn/` – Database Connection

* Usually contains `db.js` or similar to connect MongoDB using Mongoose.
* Used in `app.js` to ensure the backend can talk to the database.

---

### 📁 `models/` – Mongoose Schemas (Database Blueprints)

* These define what data will be stored in MongoDB.

| File       | Purpose                                                   |
| ---------- | --------------------------------------------------------- |
| `book.js`  | Structure of a book (title, author, price, etc.)          |
| `order.js` | Structure of an order (user, books, status, etc.)         |
| `user.js`  | Structure of a user (email, password, cart, orders, etc.) |

Used in route files to interact with MongoDB.

---

### 📁 `routes/` – API Route Handlers

These files handle specific types of requests from the frontend.

| File           | What It Does                                         |
| -------------- | ---------------------------------------------------- |
| `user.js`      | Signup, login, get user info                         |
| `userAuth.js`  | Middleware to protect routes using JWT               |
| `book.js`      | APIs to add, update, get or delete books             |
| `cart.js`      | Add/remove items to/from cart                        |
| `favourite.js` | Add/remove favourite books                           |
| `order.js`     | Place orders, get order history, update order status |

They use models (from `models/`) to read/write to the database.

---

### 📄 `.env` – Environment Variables

* Stores sensitive data like database URL, JWT secret, etc.
* Not pushed to GitHub.
* Example:

  ```
  MONGO_URL=mongodb+srv://your-url
  JWT_SECRET=your-secret
  ```

---

### 📁 `node_modules/` – Dependencies

* Automatically created when you run `npm install`.
* Contains all installed packages (Express, Mongoose, etc.).

---

### 📄 `package.json` – Project Info & Dependencies

* Lists project name, version, scripts, and dependencies.
* Used by Node.js and npm.

---

### 📄 `package-lock.json` – Exact Dependency Versions

* Automatically generated.
* Ensures consistent installs across environments.

---

## 🧠 Summary Flow

1. `app.js` starts the server and loads routes.
2. Each route file (like `user.js`, `order.js`) handles API requests.
3. These route files use **models** (like `user.js`, `book.js`) to interact with MongoDB.
4. The conn folder sets up MongoDB connection.
5. userAuth.js protects private routes using JWT.
6. `.env` stores secrets like DB URL and token secret.

---
