'use strict';

const fs = require('fs');
const path = require('path');

module.exports = (app, db) => {

    /**
     * GET /v1/order
     * @summary Use to list all available beer
     * @tags beer
     */
    app.get('/v1/order', (req, res) => {
        db.beer.findAll({
            attributes: ['id', 'name', 'type']
        })
        .then(beer => {
            res.json(beer);
        });
    });

    /**
     * GET /v1/beer-pic/
     * @summary Get a picture of a beer
     * @tags beer
     */
    app.get('/v1/beer-pic/', (req, res) => {

        const filename = req.query.picture;

        if (!filename) {
            return res.status(400).send('Missing picture parameter');
        }

        // SECURITY: Force usage of specific directory and clean filename
        const uploadsDir = path.join(__dirname, '../../../uploads');
        const safeFileName = path.basename(filename);
        const safePath = path.join(uploadsDir, safeFileName);

        // Ensure no directory escape
        if (!safePath.startsWith(uploadsDir)) {
            return res.status(403).send('Access denied');
        }

        // Allow only images
        if (
            !safeFileName.endsWith('.jpg') &&
            !safeFileName.endsWith('.jpeg') &&
            !safeFileName.endsWith('.png')
        ) {
            return res.status(400).send('Invalid file type');
        }

        // nosemgrep: semgrep-rules.node-lfi-path-traversal
        fs.readFile(safePath, (err, data) => {
            if (err) {
                return res.status(404).send('File not found');
            }

            if (safeFileName.endsWith('.png')) {
                res.type('image/png');
            } else {
                res.type('image/jpeg');
            }

            res.send(data);
        });
    });

    /**
     * GET /v1/search/{filter}/{query}
     * @summary Search for a specific beer
     * @tags beer
     */
    app.get('/v1/search/:filter/:query', (req, res) => {

        const filter = req.params.filter;
        const query = req.params.query;

        // SECURITY: Whitelist allowed columns
        const allowedFilters = ['id', 'name', 'type'];

        if (!allowedFilters.includes(filter)) {
            return res.status(400).send('Invalid filter');
        }

        const sql = `SELECT * FROM beers WHERE ${filter} = :query`;

        db.sequelize.query(sql, {
            replacements: { query },
            type: db.sequelize.QueryTypes.SELECT
        })
        .then(beers => {
            res.status(200).json(beers);
        })
        .catch(() => {
            res.status(500).send('Query failed');
        });
    });

};
