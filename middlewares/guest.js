function isGuest(req, res, next) {
  if (!req.isAuthenticated()) {
    return next();
  } else {
    return res.redirect('/home');
  }
}

module.exports = {
  isGuest,
};
