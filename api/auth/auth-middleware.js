const { JWT_SECRET } = require('../secrets')
const jwt = require('jsonwebtoken')
const User = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if (!token)
    return next({
      status: 401,
      message: 'Token required',
    })

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err)
      return next({
        status: 401,
        message: 'Token invalid',
        realErrorMessage: err.message,
      })
    req.decodedJwt = decoded
    next()
  })
}

const only = (role_name) => (req, res, next) => {
  const { decodedJwt } = req
  if (decodedJwt.role_name === role_name) {
    next()
  } else {
    next({
      status: 403,
      message: 'This is not for you',
    })
  }
}
const checkUsernameExists = async (req, res, next) => {
  try {
    const [user] = await User.findBy({ username: req.body.username })
    if (!user) {
      next({ status: 401, message: 'Invalid credentials' })
    } else {
      req.user = user
      next()
    }
  } catch (err) {
    next(err)
  }
}

const validateRoleName = (req, res, next) => {
  let { role_name } = req.body

  if (role_name) {
    role_name = req.body.role_name.trim()
  }
  if (!role_name) {
    req.role_name = 'student'
    next()
  } else if (role_name.trim() === 'admin') {
    next({ status: 422, message: 'Role name can not be admin' })
  } else if (role_name.trim().length > 32) {
    next({
      status: 422,
      message: 'Role name can not be longer than 32 chars',
    })
  } else {
    req.role_name = role_name
    next()
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
