const dns = require("node:dns");
dns.setServers(["8.8.8.8", "8.8.4.4"]);

require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const app = express();
app.set("trust proxy", 1);

const saltRounds = 12;
const PORT = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

/* Secret Information */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));

const encodedPassword = encodeURIComponent(mongodb_password);

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${encodedPassword}@${mongodb_host}/${mongodb_session_database}?retryWrites=true&w=majority`,
  collectionName: "sessions",
  //   crypto: {
  //     secret: mongodb_session_secret,
  //   },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
      secure: false,
      httpOnly: true,
      maxAge: expireTime,
    },
  }),
);

//Middleware

app.use((req, res, next) => {
  // Instead of the whole 'req', just pass the session or user status
  res.locals.authenticated = req.session.authenticated;
  res.locals.userType = req.session.user_type;
  res.locals.currentPath = req.path;
  next();
});

function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
}

function isAdmin(req, res, next) {
  if (req.session.user_type === "admin") {
    return next();
  }
  // Render your custom 403 error page
  res.status(403).render("errorMessage", {
    statusCode: 403,
    statusText: "Forbidden",
    error: "Admin access only.",
  });
}
// --- ROUTES ---

// 1. Home Page
app.get("/", (req, res) => {
  res.render("index", {
    authenticated: req.session.authenticated,
    name: req.session.name,
  });
});

// 2. Signup Page (GET)
app.get("/signup", (req, res) => {
  res.render("signup");
});

// 3. Login Page (GET)
app.get("/login", (req, res) => {
  res.render("login");
});

// 4. Signup (POST)
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  // ... (Your Joi validation logic here) ...
  const schema = Joi.object({
    name: Joi.string().max(20).required(),

    email: Joi.string().email().required(),

    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });

  // If Joi finds an issue, re-render the signup page
  if (validationResult.error) {
    return res.render("signup", {
      error: validationResult.error.details[0].message,
    });
  }

  const type = "user";

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({
    name,
    email,
    password: hashedPassword,
    type: type,
  });

  req.session.authenticated = true;
  req.session.name = name;
  req.session.type = type;
  res.redirect("/members");
});

// 5. Login (POST)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  // ... (Your Joi validation logic here) ...
  const schema = Joi.object({
    email: Joi.string().email().required(),

    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });

  // If Joi finds an issue, re-render the login page
  if (validationResult.error) {
    return res.render("login", {
      error: validationResult.error.details[0].message,
    });
  }

  const user = await userCollection.findOne({ email: email });
  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.user_type = user.type;
    res.redirect("/members");
  } else {
    return res.render("login", {
      error: "Invalid email/password. Try again",
    });
    res.send();
  }
});

// 6. Members Only Page
app.get("/members", isAuthenticated, (req, res) => {
  // Pass the full array to the template
  const images = ["fluffy.gif", "socks.gif", "catjam-jam.gif"];

  res.render("members", {
    name: req.session.name,
    images: images, // Changed from 'image' to 'images'
  });
});

//7. Admin
app.get("/admin", isAuthenticated, isAdmin, async (req, res) => {
  try {
    // 3. Fetch all users from MongoDB (assuming 'userCollection' is your collection variable)
    const users = await userCollection
      .find()
      .project({ name: 1, type: 1, _id: 1 })
      .toArray();

    res.render("admin", {
      users: users,
      currentUserName: req.session.name,
    });
  } catch (err) {
    res.status(500).send("Error fetching users from database.");
  }
});

//8. Promote
app.get("/promote", async (req, res) => {
  if (req.session.user_type !== "admin") {
    return res.status(403).send("Unauthorized");
  }

  // Validate the query parameter
  const schema = Joi.string().required();
  const validationResult = schema.validate(req.query.name);

  if (validationResult.error) {
    return res.redirect("/admin");
  }

  const userName = req.query.name;
  await userCollection.updateOne(
    { name: userName },
    { $set: { type: "admin" } },
  );

  res.redirect("/admin");
});

//9. Demote
app.get("/demote", async (req, res) => {
  if (req.session.user_type !== "admin") {
    return res.status(403).send("Unauthorized");
  }

  // Validate the query parameter
  const schema = Joi.string().required();
  const validationResult = schema.validate(req.query.name);

  if (validationResult.error) {
    return res.redirect("/admin");
  }

  const userName = req.query.name;
  await userCollection.updateOne(
    { name: userName },
    { $set: { type: "user" } },
  );

  res.redirect("/admin");
});

// 10. Logout

app.get("/logout", (req, res) => {
  req.session.destroy();

  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

// 11. 404 Page
app.use((req, res) => {
  res
    .status(404)
    .render("errorMessage", { statusCode: "404", error: "Page not found" });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
