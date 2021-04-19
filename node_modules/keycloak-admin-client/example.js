'use strict';

const adminClient = require('./');

const settings = {
  baseUrl: 'http://127.0.0.1:8080/auth',
  username: 'admin',
  password: 'admin',
  grant_type: 'password',
  client_id: 'admin-cli'
};

adminClient(settings)
  .then((client) => {
    client.realms.find()
      .then((realms) => {
        console.log('realms', realms);
      });
  })
  .catch((err) => {
    console.log('Error', err);
  });
