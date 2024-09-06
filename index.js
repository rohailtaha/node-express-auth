require('dotenv').config();
const express = require('express');
const app = express();
const expressSession = require('express-session');
const path = require('path');
const MongoStore = require('connect-mongo');
const { authRouter } = require('./auth-router');
const { passport } = require('./passport-config');
const { isGuest } = require('./middlewares/guest');
const { isAuthenticated } = require('./middlewares/authentication');
const cors = require('cors');

// app.use(cors());
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
  res.header(
    'Access-Control-Allow-Headers',
    'Origin, X-Requested-With, Content-Type, Accept'
  );
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(
  expressSession({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.DATABASE_CONNECTION,
      dbName: process.env.DATABASE_NAME,
    }),
  })
);

app.use(passport.initialize());
app.use(passport.session());
app.use(authRouter);

app.get('/login', isGuest, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/login.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.js'));
});

app.get('/signup', isGuest, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

app.get('/signup.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.js'));
});

app.get('/home', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/about', isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`server started on port ${PORT}`);
});
