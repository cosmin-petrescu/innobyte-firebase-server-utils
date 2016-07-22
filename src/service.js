"use strict";

const q = require('q'),
    firebase = require('firebase');

const Service = {

    /**
     * Verify that uid and token match. Use as middleware on routes that require admin access.
     *
     * @param req
     * @param res
     * @param next
     */
    verifyAuth: function (req, res, next) {
        const deferred = q.defer(),
            error = {
                message: 'Unauthorized request',
                code: 'INVALID_REQUEST'
            },
            token = req.header('x-auth-token'),
            uid = req.header('x-auth-uid'),
            auth = firebase.auth();

        if (!token || !uid) {
            res.status(401).end(JSON.stringify(error));
        }

        auth.verifyIdToken(token)
            .then(function (decodedToken) {
                if (uid !== decodedToken.sub) {
                    return deferred.reject(error);
                }

                deferred.resolve(true);
            })
            .catch(function () {
                deferred.reject(error);
            });

        deferred.promise
            .then(function () {
                next();
            })
            .catch(function (error) {
                res.status(401).end(JSON.stringify(error));
            });
    },

    /**
     * Verifies that user is admin. Use as middleware on routes that require admin access.
     *
     * @param req
     * @param res
     * @param next
     */
    verifyAdmin: function (req, res, next) {
        const deferred = q.defer(),
            uid = req.header('x-auth-uid'),
            db = firebase.database().ref();

        db.child('users/' + uid)
            .once('value', function (snapshot) {
                if (snapshot.exists()) {
                    if (!snapshot.val().admin) {
                        deferred.reject(false);
                    } else {
                        deferred.resolve(true);
                    }
                } else {
                    deferred.reject(false);
                }
            });

        deferred.promise
            .then(function () {
                next();
            })
            .catch(function () {
                res.status(403).end(JSON.stringify({message: 'Forbidden request', code: 'INVALID_REQUEST'}));
            });
    }
};

module.exports = Service;
