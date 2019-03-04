const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcryptjs = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  const hash = bcryptjs.hashSync(user.password, 16);

  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcryptjs.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function restricted(req, res, next) {
  let { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcryptjs.compareSync(password, user.password)) {
          next()
        } else {
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json({ message: 'Ran into an error.' });
      });
  } else {
    res.status(400).json({ message: 'No creditials provided.' });
  }


}

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
})

// server.get('/api/users', async (req, res) => {
//   let { username, password } = req.body
//   try {
//     const user = await Users.findBy({ username }).first()
//     if (user && bcryptjs.compareSync(password, user.password)) {
//       const users = await Users.find()
//       res.json(users)
//     } else {
//       res.status(401).json({ message: "invalid credentials" })
//     }
//   } catch (error) {
//     console.log(error)
//     res.status(500).json(error)
//   }
// });

// server.get('/api/users', (req, res) => {

//   Users.find()
//     .then(users => {
//       console.log(users)

//       res.json(users);
//     })
//     .catch(err => res.send(err));
// });

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
