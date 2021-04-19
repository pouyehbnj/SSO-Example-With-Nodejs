'use strict';

const privates = require('./private-map');
const request = require('request');

/**
 * @module clients
 */

module.exports = {
  find: find,
  create: create
};

/**
  A function to get the all the roles of a realm or a specific role for a realm
  @param {string} realmName - The name of the realm (not the realmID) where the client roles exist - ex: master
  @param {string} id - The id of the client (not the client-id) whose roles should be found
  @param {string} roleName - Optional name of a specific client role to find
  @returns {Promise} A promise that will resolve with the Array of roles or just one role if the roleName option is used
  @example
  keycloakAdminClient(settings)
    .then((client) => {
      client.realms.roles.find(realmName)
        .then((clientRoles) => {
          console.log(clientRoles)
      })
    })
 */
function find (client) {
  return function find (realmName, roleName) {
    return new Promise((resolve, reject) => {
      const req = {
        auth: {
          bearer: privates.get(client).accessToken
        },
        json: true
      };

      if (roleName) {
        req.url = `${client.baseUrl}/admin/realms/${realmName}/roles/${roleName}`;
      } else {
        req.url = `${client.baseUrl}/admin/realms/${realmName}/roles`;
      }

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

/**
  A function to create a new realm role.
  @param {string} realmName - The name of the realm (not the realmID) where the client roles exist - ex: master
  @param {object} newRole - The JSON representation of a role - http://www.keycloak.org/docs-api/3.0/rest-api/index.html#_rolerepresentation - name must be unique within the client
  @returns {Promise} A promise that will resolve with the newly created realm role
  @example
  keycloakAdminClient(settings)
    .then((client) => {
      client.realms.roles.create(realmName, newRole)
        .then((createRole) => {
        console.log(createRole) // [{...}]
      })
    })
 */
function create (client) {
  return function create (realm, newRole) {
    return new Promise((resolve, reject) => {
      if (!newRole) {
        return reject(new Error('role is missing'));
      }

      const req = {
        url: `${client.baseUrl}/admin/realms/${realm}/roles`,
        auth: {
          bearer: privates.get(client).accessToken
        },
        body: newRole,
        method: 'POST',
        json: true
      };

      request(req, (err, resp, body) => {
        if (err) {
          return reject(err);
        }

        if (resp.statusCode !== 201) {
          return reject(body);
        }

        // Since the create Endpoint returns an empty body, go get what we just imported.
        return resolve(client.realms.roles.find(realm, newRole.name));
      });
    });
  };
}
