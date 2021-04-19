'use strict';

const privates = require('./private-map');
const request = require('request');

/**
 * @module clients
 */

module.exports = {
  map: map,
  unmap: unmap
};

/**
  A function to map one or more client roles to a given user
  @param {string} realmName - The name of the realm (not the realmID) where the client roles exist - ex: master
  @param {string} usrid - The id of the user (UUID)
  @param {string} clientid - The id of the client (not the client-id) owning the roles
  @param {string} roles - Array containing client roles to be assigned
  @returns {Promise} A promise that will resolve with the Array of roles
  @example
  keycloakAdminClient(settings)
    .then((client) => {
      client.clients.maps.map(realmName, usrid, clientid, roles)
        .then((assignedClientRoles) => {
          console.log(assignedClientRoles)
      })
    })
 */
function map (client) {
  return function map (realmName, usrid, clientid, roles) {
    return new Promise((resolve, reject) => {
      if (!usrid) {
        return reject(new Error('user id is missing'));
      }

      if (!clientid) {
        return reject(new Error('client id is missing'));
      }

      if (!roles || !(roles instanceof Array) || roles.length === 0) {
        return reject(new Error('roles are missing'));
      }

      const req = {
        url: `${client.baseUrl}/admin/realms/${realmName}/users/${usrid}/role-mappings/clients/${clientid}`,
        auth: {
          bearer: privates.get(client).accessToken
        },
        body: roles,
        method: 'POST',
        json: true
      };

      request(req, (err, resp, body) => {
        if (err) {
          return reject(err);
        }

        if (resp.statusCode !== 204) {
          return reject(body);
        }

        return resolve(body);
      });
    });
  };
}

/**
  A function to unmap one or more client roles from a given user
  @param {string} realmName - The name of the realm (not the realmID) where the client roles exist - ex: master
  @param {string} usrid - The id of the user (UUID)
  @param {string} clientid - The id of the client (not the client-id) owning the roles
  @param {string} roles - Array containing client roles to be unassigned
  @returns {Promise} A promise that will resolve with the Array of roles
  @example
  keycloakAdminClient(settings)
    .then((client) => {
      client.clients.maps.unmap(realmName, usrid, clientid, roles)
        .then((unassignedClientRoles) => {
          console.log(unassignedClientRoles)
      })
    })
 */
function unmap (client) {
  return function unmap (realmName, usrid, clientid, roles) {
    return new Promise((resolve, reject) => {
      if (!usrid) {
        return reject(new Error('user id is missing'));
      }

      if (!clientid) {
        return reject(new Error('client id is missing'));
      }

      if (!roles || !(roles instanceof Array) || roles.length === 0) {
        return reject(new Error('roles are missing'));
      }

      const req = {
        url: `${client.baseUrl}/admin/realms/${realmName}/users/${usrid}/role-mappings/clients/${clientid}`,
        auth: {
          bearer: privates.get(client).accessToken
        },
        body: roles,
        method: 'DELETE',
        json: true
      };

      request(req, (err, resp, body) => {
        if (err) {
          return reject(err);
        }

        if (resp.statusCode !== 204) {
          return reject(body);
        }

        return resolve(body);
      });
    });
  };
}
