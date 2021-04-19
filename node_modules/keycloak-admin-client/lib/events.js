'use strict';

const request = require('request');

const privates = require('./private-map');

module.exports = {
  find: find
};

function find (client) {
  return function find (realmName, options) {
    return new Promise((resolve, reject) => {
      options = options || {};
      const req = {
        auth: {
          bearer: privates.get(client).accessToken
        },
        json: true
      };

      req.url = `${client.baseUrl}/admin/realms/${realmName}/events`;
      req.qs = options;

      request(req, (err, resp, body) => {
        if (err) {
          return reject(err);
        }

        if (resp.statusCode !== 200) {
          return reject(body);
        }

        return resolve(body);
      });
    });
  };
}
