function isAuthenticated(req, res, next) {
  console.log(req.session, req.isAuthenticated());
  if (req.isAuthenticated()) {
    return next();
  } else {
    return res.redirect('/login');
  }
}

module.exports = {
  isAuthenticated,
};
