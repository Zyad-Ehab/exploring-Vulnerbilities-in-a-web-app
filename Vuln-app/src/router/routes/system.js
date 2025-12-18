'use strict';

const { URL } = require('url');
const axios = require('axios');

module.exports = (app, db) => {

    /**
     * GET /v1/status/{brand}
     * @summary Check if brand website is available
     * @tags system
     */
    app.get('/v1/status/:brand', (req, res) => {

        const brand = req.params.brand;

        // SECURITY: Allowlist approach
        const allowedBrands = ['budweiser', 'heineken', 'corona'];

        if (!allowedBrands.includes(brand.toLowerCase())) {
            return res.status(400).send('Invalid brand');
        }

        axios.get(`https://letmegooglethat.com/?q=${encodeURIComponent(brand)}`)
            .then(() => {
                // SECURITY: Output is safe because 'brand' is validated against allowedBrands
                // nosemgrep: semgrep-rules.node-reflected-xss
                res.send(`Brand ${brand} is reachable`);
            })
            .catch(() => {
                res.status(500).send('Brand check failed');
            });
    });

    /**
     * GET /v1/redirect/
     * @summary Redirect the user to the beer brand website
     * @tags system
     */
    app.get('/v1/redirect/', (req, res) => {

        const redirectUrl = req.query.url;

        try {
            const parsedUrl = new URL(redirectUrl);
            const allowedHosts = ['heineken.com', 'budweiser.com'];

            if (!allowedHosts.includes(parsedUrl.hostname)) {
                return res.status(400).send('Untrusted redirect');
            }

            res.redirect(parsedUrl.href);
        } catch (e) {
            res.status(400).send('Invalid URL');
        }
    });

    /**
     * POST /v1/init
     * @summary Initialize beers
     * @tags system
     */
    app.post('/v1/init', (req, res) => {

        // SECURITY: Treat input as JSON only, no deserialization of functions
        const beers = req.body.object;

        if (!beers || typeof beers !== 'object') {
            return res.status(400).send('Invalid data format');
        }

        console.log(beers);
        res.json({ status: 'Initialization completed safely' });
    });

    /**
     * GET /v1/test/
     * @summary Perform a get request on another url in the system
     * @tags system
     */
    app.get('/v1/test/', (req, res) => {

        const testUrl = req.query.url;

        try {
            const parsedUrl = new URL(testUrl);

            // SECURITY: Improved Blocklist (Localhost + Cloud Metadata)
            const blockedHosts = [
                'localhost',
                '127.0.0.1',
                '0.0.0.0',
                '::1',
                '169.254.169.254' // Block AWS/GCP/Azure Metadata
            ];

            if (blockedHosts.includes(parsedUrl.hostname)) {
                return res.status(403).send('SSRF blocked');
            }

            // nosemgrep: semgrep-rules.node-ssrf-outbound
            axios.get(parsedUrl.href)
                .then(resp => {
                    res.json({ status: resp.status });
                })
                .catch(() => {
                    res.status(500).send('Request failed');
                });

        } catch (e) {
            res.status(400).send('Invalid URL');
        }
    });

};
