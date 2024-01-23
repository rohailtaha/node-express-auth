require('dotenv').config();
const express = require('express');
const { getDatabase } = require('./lib/database');
const { body, validationResult } = require('express-validator');
const LocalStrategy = require('passport-local');
const passport = require('passport');
const app = express();
const { hashPassword, verifyPassword } = require('./lib/utils');
const expressSession = require('express-session');
const { ObjectId } = require('mongodb');
const path = require('path');
const { isAuthenticated } = require('./middlewares/authentication');
const { isGuest } = require('./middlewares/guest');

app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

app.use(
  expressSession({
    secret: 'hello',
    resave: false,
    saveUninitialized: false,
  })
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  const db = await getDatabase();
  const user = await db.collection('users').findOne({
    _id: new ObjectId(id),
  });
  done(null, { email: user.email, _id: user._id });
});

passport.use(
  new LocalStrategy(async function verify(username, password, cb) {
    console.log(username, password);
    const db = await getDatabase();
    try {
      const user = await db.collection('users').findOne({
        email: username,
      });
      const passwordVerified = await verifyPassword(password, user.password);
      if (passwordVerified) {
        cb(null, { email: user.email, _id: user._id });
      } else {
        throw new Error('Invalid password');
      }
    } catch (err) {
      cb(err, null);
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

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

app.post(
  '/auth/signup',
  body('name').isString().notEmpty().isLength({ min: 1 }),
  body('email').isEmail(),
  body('password').isString().notEmpty().isLength({ min: 5 }),
  async (req, res) => {
    const result = validationResult(req);

    if (!result.isEmpty()) {
      return res.status(400).end('Invalid data');
    }

    const { password } = req.body;

    const hashedPassword = await hashPassword(password);
    const db = await getDatabase();

    try {
      let user = await db.collection('users').findOne({
        email: req.body.email,
      });

      if (user) {
        return res
          .status(400)
          .json({ message: 'The user with this email already exists' });
      }

      const { insertedId } = await db.collection('users').insertOne({
        ...req.body,
        password: hashedPassword,
      });

      user = await db.collection('users').findOne({
        _id: insertedId,
      });

      req.login({ email: user.email, _id: user._id }, err => {
        if (err) return res.status(500).end();
        return res.redirect('/home');
      });
    } catch (e) {
      console.error(e);
      return res.status(500).end();
    }
  }
);

app.post(
  '/auth/login',
  passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/login',
  })
);

app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).end();
    res.redirect('/login');
  });
});

app.listen(3000, () => {
  console.log('server started on port 3000');
});
