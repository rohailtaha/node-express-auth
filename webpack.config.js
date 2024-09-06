const path = require('path');

module.exports = {
  // mode: 'production',
  mode: 'development',
  entry: './index.js',
  output: {
    path: path.join(__dirname, 'dist'),
    filename: 'index.js',
  },
};
