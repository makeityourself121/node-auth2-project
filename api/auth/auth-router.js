const router = require('express').Router()
const { checkUsernameExists, validateRoleName } = require('./auth-middleware')

const bcrypt = require('bcryptjs')

const Users = require('../users/users-model')
const tokenBuilder = require('./token-builder')

router.post('/register', validateRoleName, (req, res, next) => {
  const { username, password } = req.body
  const { role_name } = req
  const rounds = process.env.BCRYPT_ROUNDS || 8
  const hash = bcrypt.hashSync(password, rounds)

  Users.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser)
    })
    .catch(next)
})

router.post('/login', checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body

  Users.findBy({ username }).then(([user]) => {
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = tokenBuilder(user)
      res.status(200).json({
        message: `${user.username} is back!`,
        token,
      })
    } else {
      next({ status: 401, message: 'Invalid credentials' })
    }
  })
})

module.exports = router
