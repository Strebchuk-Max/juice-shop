import path = require('path');
import { type Request, type Response, type NextFunction } from 'express';
import { challenges } from '../data/datacache';
import challengeUtils = require('../lib/challengeUtils');
import * as utils from '../lib/utils';
const security = require('../lib/insecurity');

module.exports = function servePublicFiles() {
    return ({ params }: Request, res: Response, next: NextFunction) => {
        try {
            const file = sanitizeFileName(params.file);

            if (!file) {
                return res.status(400).send('Invalid file name.');
            }

            if (isValidFile(file)) {
                const safeBasePath = path.resolve('ftp/');
                const resolvedPath = path.resolve(safeBasePath, file);

                if (!resolvedPath.startsWith(safeBasePath)) {
                    return res.status(403).send('Access denied!');
                }

                challengeUtils.solveIf(challenges.directoryListingChallenge, () =>
                    file.toLowerCase() === 'acquisitions.md'
                );

                verifySuccessfulPoisonNullByteExploit(file);
                return res.sendFile(resolvedPath);
            } else {
                res.status(403).send('Only .md and .pdf files are allowed!');
            }
        } catch (error) {
            next(error);
        }
    };

    function isValidFile(file: string): boolean {
        return (
            endsWithAllowlistedFileType(file) ||
            file === 'incident-support.kdbx'
        );
    }

    function verifySuccessfulPoisonNullByteExploit(file: string) {
        challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () =>
            file.toLowerCase() === 'eastere.gg'
        );

        challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () =>
            file.toLowerCase() === 'package.json.bak'
        );

        challengeUtils.solveIf(challenges.forgottenBackupChallenge, () =>
            file.toLowerCase() === 'coupons_2013.md.bak'
        );

        challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () =>
            file.toLowerCase() === 'suspicious_errors.yml'
        );

        challengeUtils.solveIf(challenges.nullByteChallenge, () =>
            challenges.easterEggLevelOneChallenge.solved ||
            challenges.forgottenDevBackupChallenge.solved ||
            challenges.forgottenBackupChallenge.solved ||
            challenges.misplacedSignatureFileChallenge.solved ||
            file.toLowerCase() === 'encrypt.pyc'
        );
    }

    function endsWithAllowlistedFileType(file: string): boolean {
        return utils.endsWith(file, '.md') || utils.endsWith(file, '.pdf');
    }

    function sanitizeFileName(file: string): string | null {
        if (!file || typeof file !== 'string') return null;
        const sanitized = file.replace(/(\.\.(\/|\\|%2e%2e))/g, '');
        if (sanitized.includes('/') || sanitized.includes('\\')) return null;
        return sanitized;
    }
};
