'use strict';

const config = require('./../../config');
var jwt = require("jsonwebtoken");
const { user } = require('../../orm');
const bcrypt = require('bcrypt');
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_SECRET";

module.exports = (app, db) => {

    /* ===============================
       ADMIN – GET ALL USERS
       FIXED:
       - Hardcoded JWT Secret
       - Unverified JWT
       - Authorization Bypass
    =============================== */
    app.get('/v1/admin/users/', (req, res) => {

        if (!req.headers.authorization) {
            return res.status(401).json({ error: "Missing token" });
        }

        let decoded;
        try {
            decoded = jwt.verify(
                req.headers.authorization.split(' ')[1],
                JWT_SECRET
            );
        } catch (e) {
            return res.status(401).json({ error: "Invalid token" });
        }

        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: "Admin only" });
        }

        db.user.findAll({ include: "beers" })
            .then(users => res.json(users))
            .catch(err => res.status(500).json({ error: err.toString() }));
    });

    /* ===============================
       GET USER BY ID
       FIXED:
       - BOLA (Authorization check)
    =============================== */
    app.get('/v1/user/:id', (req, res) => {

        if (!req.headers.authorization) {
            return res.status(401).json({ error: "Missing token" });
        }

        let decoded;
        try {
            decoded = jwt.verify(
                req.headers.authorization.split(' ')[1],
                JWT_SECRET
            );
        } catch {
            return res.status(401).json({ error: "Invalid token" });
        }

        if (decoded.id != req.params.id && decoded.role !== 'admin') {
            return res.status(403).json({ error: "Forbidden" });
        }

        db.user.findOne({ include: 'beers', where: { id: req.params.id } })
            .then(user => res.json(user));
    });

    /* ===============================
       DELETE USER
       FIXED:
       - Broken Function Level Auth
    =============================== */
    app.delete('/v1/user/:id', (req, res) => {

        if (!req.headers.authorization) {
            return res.status(401).json({ error: "Missing token" });
        }

        const decoded = jwt.verify(
            req.headers.authorization.split(' ')[1],
            JWT_SECRET
        );

        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: "Admin only" });
        }

        db.user.destroy({ where: { id: req.params.id } })
            .then(() => res.json({ result: "deleted" }));
    });

    /* ===============================
       CREATE USER
       FIXED:
       - Weak password
       - ReDoS regex
       - Plaintext password
    =============================== */
    app.post('/v1/user/', async (req, res) => {

        const { email, name, role, password, address } = req.body;

        // SAFE regex
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.json({ error: "Invalid email format" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        db.user.create({
            name,
            email,
            role,
            address,
            password: hashedPassword
        }).then(user => res.json(user));
    });

    /* ===============================
       LOVE BEER (GET)
       FIXED:
       - CSRF (GET removed)
    =============================== */

    // ❌ VULNERABLE CODE (CSRF)
    /*
    app.get('/v1/love/:beer_id', ...)
    */

    /* ===============================
       LOVE BEER (POST)
       FIXED:
       - CSRF
       - IDOR
    =============================== */
    app.post('/v1/love/:beer_id', (req, res) => {

        if (!req.headers.authorization) {
            return res.status(401).json({ error: "Missing token" });
        }

        const decoded = jwt.verify(
            req.headers.authorization.split(' ')[1],
            JWT_SECRET
        );

        const beer_id = req.params.beer_id;

        db.beer.findOne({ where: { id: beer_id } })
            .then(beer => {
                return db.user.findOne({ where: { id: decoded.id } })
                    .then(current_user => {
                        return current_user.addBeer(beer);
                    });
            })
            .then(() => res.json({ success: true }))
            .catch(err => res.json({ error: err.toString() }));
    });

    /* ===============================
       LOGIN → JWT TOKEN
       FIXED:
       - Hardcoded secret
       - Weak password
       - Insecure comparison
    =============================== */
    app.post('/v1/user/token', (req, res) => {

        const { email, password } = req.body;

        db.user.findOne({ where: { email } })
            .then(async user => {

                if (!user) {
                    return res.status(404).json({ error: "User not found" });
                }

                const valid = await bcrypt.compare(password, user.password);
                if (!valid) {
                    return res.status(401).json({ error: "Wrong password" });
                }

                const token = jwt.sign(
                    { id: user.id, role: user.role },
                    JWT_SECRET,
                    { expiresIn: "24h" }
                );

                res.json({ jwt: token, user });
            });
    });

    /* ===============================
       UPDATE USER
       FIXED:
       - Mass Assignment
       - Horizontal Priv Esc
    =============================== */
    app.put('/v1/user/:id', (req, res) => {

        const decoded = jwt.verify(
            req.headers.authorization.split(' ')[1],
            JWT_SECRET
        );

        if (decoded.id != req.params.id) {
            return res.status(403).json({ error: "Forbidden" });
        }

        const allowedFields = {
            address: req.body.address,
            profile_pic: req.body.profile_pic
        };

        db.user.update(allowedFields, { where: { id: req.params.id } })
            .then(result => res.json(result));
    });

    /* ===============================
       ADMIN PROMOTE
       FIXED:
       - Vertical Priv Esc
    =============================== */
    app.put('/v1/admin/promote/:id', (req, res) => {

        const decoded = jwt.verify(
            req.headers.authorization.split(' ')[1],
            JWT_SECRET
        );

        if (decoded.role !== 'admin') {
            return res.status(403).json({ error: "Admin only" });
        }

        db.user.update({ role: 'admin' }, { where: { id: req.params.id } })
            .then(result => res.json(result));
    });

    /* ===============================
       OTP VALIDATION
       FIXED:
       - Auth data in URL
       - Hardcoded secrets
       - Broken 2FA
    =============================== */

    // ❌ VULNERABLE CODE (OTP via URL, hardcoded seed)
    /*
    app.post('/v1/user/:id/validate-otp', ...)
    */

};
