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
  crypto: {
    secret: mongodb_session_secret,
  },
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

// --- ROUTES ---

// 1. Home Page
app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
            <h1>Welcome</h1>
            <a href="/signup"><button>Sign Up</button></a>
            <a href="/login"><button>Log In</button></a>
        `);
  } else {
    res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href="/members"><button>Go to Members Area</button></a>
            <a href="/logout"><button>Logout</button></a>
        `);
  }
});

// 2. Signup Page (GET)
app.get("/signup", (req, res) => {
  res.send(`
        <h2>Create Account</h2>
        <form action="/signup" method="post">
            <input name="name" type="text" placeholder="Name"><br>
            <input name="email" type="email" placeholder="Email"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button>Submit</button>
        </form>
    `);
});

// 3. Login Page (GET)
app.get("/login", (req, res) => {
  res.send(`
    <h2>Login</h2>
    <form action="/login" method="post">
        <input name="email" type="email" placeholder="Email"><br>
        <input name="password" type="password" placeholder="Password" autocomplete="current-password"><br>
        <button>Submit</button>
    </form>
  `);
});

// 4. Signup (POST)
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const schema = Joi.object({
    name: Joi.string().max(20).required(),
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, email, password });
  if (validationResult.error) {
    res.send(
      `${validationResult.error.details[0].message}. <br><a href="/signup">Try again</a>`,
    );
    return;
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  await userCollection.insertOne({ name, email, password: hashedPassword });

  req.session.authenticated = true;
  req.session.name = name;

  res.redirect("/members");
});

// 5. Login (POST)
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ email, password });
  if (validationResult.error) {
    res.redirect("/login");
    return;
  }

  const user = await userCollection.findOne({ email: email });

  if (user && (await bcrypt.compare(password, user.password))) {
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    res.redirect("/members");
  } else {
    res.send(
      "Invalid email/password combination. <br><a href='/login'>Try again</a>",
    );
  }
});

// 6. Members Only Page
app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/");
    return;
  }

  const images = ["fluffy.gif", "socks.gif", "catjam-jam.gif"];
  const randomIndex = Math.floor(Math.random() * images.length);
  const selectedImage = images[randomIndex];

  res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src="/${selectedImage}" style="width:300px;"><br>
        <a href="/logout"><button>Sign out</button></a>
    `);
});

// 7. Logout
app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

// 8. 404 Page
app.use((req, res) => {
  res.status(404).send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
