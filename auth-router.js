const router = require('express').Router();
const { body, validationResult } = require('express-validator');
const { passport } = require('./passport-config');
const { hashPassword } = require('./lib/utils');

router.post(
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

router.post(
  '/auth/login',
  passport.authenticate('local', {
    successRedirect: '/home',
    failureRedirect: '/login',
  })
);

router.get(
  '/auth/github',
  passport.authenticate('github', {
    scope: ['user:email'],
  })
);

router.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    successRedirect: '/home',
    failureRedirect: '/login',
  })
);

router.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

router.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    successRedirect: '/home',
    failureRedirect: '/login',
  })
);

router.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) return res.status(500).end();
    req.session.destroy(err => {
      if (err) return res.status(500).end();
      return res.redirect('/login');
    });
  });
});

module.exports = {
  authRouter: router,
};
