# Backend

- setup .env file
    - JWT_SECRET=8a7d76e7f5b86cc67...
        - Generate JWT secret by running node in cmd line
        - const crypto = require('crypto')
        - crypto.randomBytes(64).toString('hex')
    - EMAIL_PASSWORD_SECRET=9785a95f95e595c9559d59...
    - DB_PASSWORD_SECRET=9785be97945ad9835...