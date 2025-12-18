'use strict';

const escape = require('escape-html');
// SECURITY: Use bcrypt for password hashing
const bcrypt = require('bcrypt'); 

module.exports = (app, db) => {

    // ===============================
    // Front End entry page
    // ===============================
    app.get('/', (req, res) => {
        const message = req.query.message || "Please log in to continue";
        
        // SECURITY: Escape input
        res.locals.message = escape(message);
        
        // nosemgrep: semgrep-rules.node-reflected-xss
        res.render('user.html');
    });

    // ===============================
    // Front End register page
    // ===============================
    app.get('/register', (req, res) => {
        const message = req.query.message || "Please log in to continue";
        
        // SECURITY: Escape input
        res.locals.message = escape(message);
        
        // nosemgrep: semgrep-rules.node-reflected-xss
        res.render('user-register.html');
    });

    // ===============================
    // Register form
    // ===============================
    app.get('/registerform', async (req, res) => {

        const { email, name, password, address } = req.query;

        if (!email || !name || !password || !address) {
            res.redirect('/register?message=Missing required fields');
            return;
        }

        const emailExpression = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;

        if (!emailExpression.test(email)) {
            res.redirect("/register?message=Email couldn't be validated");
            return;
        }

        try {
            // SECURITY: Hash password with Bcrypt (Salt rounds: 10)
            const hashedPassword = await bcrypt.hash(password, 10);

            await db.user.create({
                name,
                email,
                role: 'user',
                address,
                password: hashedPassword
            });

            res.redirect('/?message=Registration successful');

        } catch (e) {
            console.error(e);
            res.redirect('/?message=Registration error');
        }
    });

    // ===============================
    // Login
    // ===============================
    app.get('/login', async (req, res) => {

        const { email, password } = req.query;

        if (!email || !password) {
            res.redirect('/?message=Missing credentials');
            return;
        }

        const user = await db.user.findOne({ where: { email } });

        // SECURITY: Check if user exists, then compare hash using Bcrypt
        if (!user) {
            res.redirect('/?message=Invalid credentials');
            return;
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            res.redirect('/?message=Invalid credentials');
            return;
        }

        req.session.logged = true;
        req.session.userId = user.id;
        res.redirect('/profile');
    });

    // ===============================
    // Profile
    // ===============================
    app.get('/profile', async (req, res) => {

        if (!req.session.logged) {
            res.redirect('/?message=Please login first');
            return;
        }

        const user = await db.user.findOne({
            where: { id: req.session.userId },
            include: ['beers']
        });

        res.render('profile.html', { user });
    });

    // ===============================
    // Beer page
    // ===============================
    app.get('/beer', async (req, res) => {

        if (!req.session.logged) {
            res.redirect('/?message=Login required');
            return;
        }

        const beerId = parseInt(req.query.id);
        if (!beerId) {
            res.redirect('/?message=Invalid beer');
            return;
        }

        const beer = await db.beer.findOne({
            where: { id: beerId }
        });

        let love_message = "Enjoy your beer";

        // SECURITY: Output encoding
        if (req.query.relationship) {
            love_message = escape(req.query.relationship);
        }

        res.locals.message = love_message;
        
        // nosemgrep: semgrep-rules.node-reflected-xss
        res.render('beer.html', { beers: [beer] });
    });
};
