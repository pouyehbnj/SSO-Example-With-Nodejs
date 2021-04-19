'use strict';

const request = require('request-promise-native');
const Keycloak = require('keycloak-connect');
const jwt = require('jsonwebtoken');
const KeyCloakCookieStore = require('../lib/keyCloakCookieStore');


class KeyCloakService {

    
    /**
     *
     * @param permissions
     * @param config 
     *  can be:
     *      undefined (not specified) - the configuration will be loaded from 'keycloak.json'
     *      string - config will be loaded from a file
     *      object - parameters from this object
     */
    constructor(permissions,config) {
        // let config = {
        //     "realm": "CAMPAIGN_REALM",
        //     "auth-server-url": "http://localhost:8080/auth",
        //     "ssl-required": "external",
        //     "resource": "CAMPAIGN_CLIENT",
        //     "verify-token-audience": true,
        //     "credentials": {
        //       "secret": "6d979be5-cb81-4d5c-9fc7-45d1b0c7a75e"
        //     },
        //     "confidential-port": 0,
        //     "policy-enforcer": {}
        //   }
        console.log('1')
        console.log(config)
        this.permissions = permissions;
        this.keyCloak = KeyCloakService.initKeyCloak(config);
        this.keyCloakProtect = this.keyCloak.protect();
        this.entitlementUrl = KeyCloakService.createEntitlementUrl(this.keyCloak);
    }

    static initKeyCloak(config) {
        console.log('2')
        let result = new Keycloak(
            {
                cookies: true
            },
            KeyCloakService.createKeyCloakConfig(config)
        );

        // replace CookieStore from keycloak-connect
        result.stores[1] = KeyCloakCookieStore;

        // disable redirection to Keycloak login page
        result.redirectToLogin = () => false;

        // TODO It is not necessary, this function returns 403 by default. Just to having redirect to a page.
        // This function is used in other KeyCloakService methods
        console.log('heree1')
        result.accessDenied = (request, response) => response.redirect('/accessDenied.html');
        return result;
    }

    static createKeyCloakConfig(config) {
        console.log('3')
        if (!config || typeof config === 'string') {
            return null;
        }

        const authServerUrl = `${config.serverUrl}/auth`;
        return {
            realm: config.realm,
            authServerUrl: authServerUrl,
            resource: config.resource,
            credentials: {
                secret: config.secret
            }
        };
    }

    static createEntitlementUrl(keycloak) {
        console.log('4')
        return `${keycloak.config.realmUrl}/authz/entitlement/${keycloak.config.clientId}`;
    }

    accessDenied(request, response) {
        console.log('heree2')
        this.keyCloak.accessDenied(request, response);
    }

    middleware(logoutUrl) {
        console.log('5')
        // Return the Keycloak middleware.
        //
        // Specifies that the user-accessible application URL to
        // logout should be mounted at /logout
        //
        // Specifies that Keycloak console callbacks should target the
        // root URL.  Various permutations, such as /k_logout will ultimately
        // be appended to the admin URL.
        let result = this.keyCloak.middleware({
            logout: logoutUrl,
            admin: '/'
        });
        result.push(this.createSecurityMiddleware());
        return result;
    }

    loginUser(login, password, request, response) {
        console.log('6')
        console.log('passwooooooooooord')
        console.log(password)
       // console.log((request))
      //  console.log((response))
        return this.keyCloak.grantManager.obtainDirectly(login, password).then(grant => {
            this.keyCloak.storeGrant(grant, request, response);
            console.log('after')
            console.log(this.keyCloak.stores)
            //console.log(err)
          //  console.log(grant)
            
            //console.log(this.keyCloak.access_token)
           // this.keyCloak.access_token.signature = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
            return grant;
        });
    }

    getUserName(request) {
        console.log('7')
        return this.getAccessToken(request)
            .then(token => Promise.resolve(jwt.decode(token).preferred_username));
    }

    getAllPermissions(request) {
        console.log('8')
        return this.getAccessToken(request)
            .then(this.getEntitlementsRequest.bind(this))
            .then(KeyCloakService.decodeRptToken);
    }

    static decodeRptToken(rptTokenResponse) {
        console.log('9')
        const rptToken = JSON.parse(rptTokenResponse).rpt;
        const rpt = jwt.decode(rptToken);
        let permissions = [];
        (rpt.authorization.permissions || []).forEach(p => permissions.push({
            scopes: p.scopes,
            resource: p.resource_set_name
        }));
        return {
            userName: rpt.preferred_username,
            roles: rpt.realm_access.roles,
            permissions: permissions
        };
    }

    /**
     * Protect with checking authentication only.
     *
     * @returns protect middleware
     */
    justProtect() {
        console.log('10')
        return this.keyCloak.protect();
    }

    protect(resource, scope) {
        console.log('11')
        return (request, response, next) =>
            this.protectAndCheckPermission(request, response, next, resource, scope);
    }

    checkPermission(request, resource, scope) {
        console.log('12')
        let scopes = [scope];
        return this.getAccessToken(request)
            .then(accessToken => this.checkEntitlementRequest(resource, scopes, accessToken));
    }

    createSecurityMiddleware() {
        console.log('13')
        return (req, res, next) => {
            if (this.permissions.isNotProtectedUrl(req)) {
                return next();
            }

            const permission = this.permissions.findPermission(req);
            if (!permission) {
                console.log('Can not find a permission for: %s %s', req.method, req.originalUrl);
                console.log('heree3')
                return this.keyCloak.accessDenied(req, res);
            }

            this.protectAndCheckPermission(req, res, next, permission.resource, permission.scope);
        };
    }

    protectAndCheckPermission(request, response, next, resource, scope) {
        console.log('14')
        this.keyCloakProtect(request, response, () => this.checkPermission(request, resource, scope)
            .then(() => next()).catch(error => {
                console.error('access denied: ' + error.message);
                console.log('heree4')
                this.keyCloak.accessDenied(request, response);
            }));
    }

    getEntitlementsRequest(accessToken) {
        console.log('15')
        let options = {
            url: this.entitlementUrl,
            headers: {
                Accept: 'application/json'
            },
            auth: {
                bearer: accessToken
            },
            method: 'GET'
        };

        return request(options);
    }

    checkEntitlementRequest(resource, scopes, accessToken) {
        console.log('16')
        let permission = {
            resource_set_name: resource,
            scopes: scopes
        };
        let jsonRequest = {
            permissions: [permission]
        };
        let options = {
            url: this.entitlementUrl,
            headers: {
                Accept: 'application/json'
            },
            auth: {
                bearer: accessToken
            },
            body: jsonRequest,
            method: 'POST',
            json: true
        };

        return request(options);
    }

    getAccessToken(request) {
        console.log('17')
        let tokens = this.keyCloak.stores[1].get(request);
        let result = tokens && tokens.access_token;
        return result ? Promise.resolve(result) : Promise.reject('There is not token.');
    }

}

module.exports = KeyCloakService;
