

const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) return res.status(401).send({ error: 'No token' });

  try {
    const decoded = jwt.verify(token, 'secret');
    req.user = decoded;
    next();
  } catch {
    res.status(400).send({ error: 'Invalid token' });
  }
};
