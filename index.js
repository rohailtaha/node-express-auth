require('dotenv').config();
const express = require('express');
const { getDatabase } = require('./lib/database');
const { body, validationResult } = require('express-validator');
const LocalStrategy = require('passport-local');
const GithubStrategy = require('passport-github2').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const passport = require('passport');
const app = express();
const { hashPassword, verifyPassword } = require('./lib/utils');
const expressSession = require('express-session');
const path = require('path');
const { isAuthenticated } = require('./middlewares/authentication');
const { isGuest } = require('./middlewares/guest');
const MongoStore = require('connect-mongo');

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

passport.use(
  new LocalStrategy(async function verify(username, password, done) {
    const db = await getDatabase();
    try {
      const user = await db.collection('users').findOne({
        email: username,
      });
      if (!user) return done(null, false);

      // check if the user logged in previously using OAuth provider.
      if (user.authenticationProvider) {
        return done(null, false);
      }

      const passwordVerified = await verifyPassword(password, user.password);
      if (passwordVerified) {
        done(null, { _id: user._id.toString() });
      } else {
        done(null, false);
      }
    } catch (err) {
      done(err, null);
    }
  })
);

passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
    },
    async function (accessToken, refreshToken, profile, done) {
      // refresh token is undefined
      const db = await getDatabase();

      const user = await db.collection('users').findOne({
        email: profile._json.email,
      });

      // save the user in db if does not already exist.
      if (!user) {
        await db.collection('users').insertOne({
          email: profile._json.email,
          name: profile._json.name,
          authenticationProvider: profile.provider,
        });
      }

      // If the user was previously logged in using another strategy than update
      // the authenticationProvider
      if (user && user.authenticationProvider !== profile.provider) {
        await db.collection('users').updateOne(
          {
            email: profile._json.email,
          },
          {
            $set: {
              name: profile._json.name,
              authenticationProvider: profile.provider,
            },
            $unset: { password: '' },
          }
        );
      }

      return done(null, { _id: profile._json.id.toString() });
    }
  )
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async function (accessToken, refreshToken, profile, done) {
      const db = await getDatabase();

      const user = await db.collection('users').findOne({
        email: profile._json.email,
      });

      if (!user) {
        await db.collection('users').insertOne({
          email: profile._json.email,
          name: profile._json.name,
          authenticationProvider: profile.provider,
        });
      }

      if (user && user.authenticationProvider !== profile.provider) {
        await db.collection('users').updateOne(
          {
            email: profile._json.email,
          },
          {
            $set: {
              name: profile._json.name,
              authenticationProvider: profile.provider,
            },
            $unset: { password: '' },
          }
        );
      }

      return done(null, { _id: profile._json.sub });
    }
  )
);

passport.serializeUser((user, done) => {
  // This function will only be called on login (we login when we signup and login)
  // The value provided to callback will be set in the session.passport.user property
  // The session id will be stored in the cookie
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  // the value provided to callback will be set to req.user
  done(null, { _id: id });
});

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

      req.login({ _id: user._id.toString() }, err => {
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

app.get(
  '/auth/github',
  passport.authenticate('github', {
    scope: ['user:email'],
  })
);

app.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    successRedirect: '/home',
    failureRedirect: '/login',
  })
);

app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/home',
    failureRedirect: '/login',
  })
);

app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).end();
    req.session.destroy(err => {
      if (err) return res.status(500).end();
      return res.redirect('/login');
    });
  });
});

app.listen(3000, () => {
  console.log('server started on port 3000');
});
