import config from 'config';
import { type Request, type Response } from 'express';
import { BasketModel } from '../models/basket';
import { UserModel } from '../models/user';
import challengeUtils = require('../lib/challengeUtils');
import * as utils from '../lib/utils';
import { challenges } from '../data/datacache';

const security = require('../lib/insecurity');
const otplib = require('otplib');

otplib.authenticator.options = {
    window: 1
};

// Verifies the user’s TOTP for 2FA
async function verify(req: Request, res: Response) {
    const { tmpToken, totpToken } = req.body;

    try {
        const { userId, type } = security.verify(tmpToken) && security.decode(tmpToken);

        if (type !== 'password_valid_needs_second_factor_token') {
            throw new Error('Invalid token type');
        }

        const user = await UserModel.findByPk(userId);
        if (user == null) {
            throw new Error('User not found');
        }

        const isValid = otplib.authenticator.check(totpToken, user.totpSecret);
        const plainUser = utils.queryResultToJson(user);

        if (!isValid) {
            return res.status(401).send({ error: 'Invalid 2FA token' });
        }

        challengeUtils.solveIf(challenges.twoFactorAuthUnsafeSecretStorageChallenge, () => {
            return user.email === 'wurstbrot@' + config.get<string>('application.domain');
        });

        const [basket] = await BasketModel.findOrCreate({ where: { UserId: userId } });

        const token = security.authorize(plainUser);
        plainUser.bid = basket.id;
        security.authenticatedUsers.put(token, plainUser);

        res.json({ authentication: { token, bid: basket.id } });
    } catch (error) {
        res.status(401).send({ error: 'Authentication failed' });
    }
}

// Checks the 2FA setup status
async function status(req: Request, res: Response) {
    try {
        const data = security.authenticatedUsers.from(req);
        if (!data) {
            throw new Error('Login required');
        }
        const { data: user } = data;

        if (user.totpSecret === '') {
            const secret = otplib.authenticator.generateSecret();

            res.json({
                setup: false,
                secret,
                setupToken: security.authorize({
                    secret,
                    type: 'totp_setup_secret'
                })
            });
        } else {
            res.json({
                setup: true
            });
        }
    } catch (error) {
        res.status(401).send({ error: 'Status check failed' });
    }
}

// Sets up 2FA for the user
async function setup(req: Request, res: Response) {
    try {
        const data = security.authenticatedUsers.from(req);
        if (!data) {
            throw new Error('Login required');
        }
        const { data: user } = data;

        const { password, setupToken, initialToken } = req.body;

        if (user.password !== security.hash(password)) {
            throw new Error('Incorrect password');
        }

        if (user.totpSecret !== '') {
            throw new Error('2FA already setup');
        }

        const { secret, type } = security.verify(setupToken) && security.decode(setupToken);
        if (type !== 'totp_setup_secret') {
            throw new Error('Invalid setup token');
        }

        if (!otplib.authenticator.check(initialToken, secret)) {
            throw new Error('Initial token invalid');
        }

        const userModel = await UserModel.findByPk(user.id);
        if (userModel == null) {
            throw new Error('User not found');
        }

        userModel.totpSecret = secret; // Ideally, this should be hashed
        await userModel.save();
        security.authenticatedUsers.updateFrom(req, utils.queryResultToJson(userModel));

        res.status(200).send();
    } catch (error) {
        res.status(401).send({ error: 'Setup failed' });
    }
}

// Disables 2FA for the user
async function disable(req: Request, res: Response) {
    try {
        const data = security.authenticatedUsers.from(req);
        if (!data) {
            throw new Error('Login required');
        }
        const { data: user } = data;

        const { password } = req.body;

        if (user.password !== security.hash(password)) {
            throw new Error('Incorrect password');
        }

        const userModel = await UserModel.findByPk(user.id);
        if (userModel == null) {
            throw new Error('User not found');
        }

        userModel.totpSecret = '';
        await userModel.save();
        security.authenticatedUsers.updateFrom(req, utils.queryResultToJson(userModel));

        res.status(200).send();
    } catch (error) {
        res.status(401).send({ error: 'Disable failed' });
    }
}

module.exports = { disable, verify, status, setup };
