import path = require('path');
import { type Request, type Response, type NextFunction } from 'express';

module.exports = function serveKeyFiles() {
    return ({ params }: Request, res: Response, next: NextFunction) => {
        try {
            const file = sanitizeFileName(params.file);

            if (!file) {
                return res.status(400).send('Invalid file name.');
            }

            const safeBasePath = path.resolve('encryptionkeys/');
            const resolvedPath = path.resolve(safeBasePath, file);

            if (!resolvedPath.startsWith(safeBasePath)) {
                return res.status(403).send('Access denied!');
            }

            res.sendFile(resolvedPath);
        } catch (error) {
            next(error);
        }
    };

    function sanitizeFileName(file: string): string | null {
        if (!file || typeof file !== 'string') return null;
        const sanitized = file.replace(/(\.\.(\/|\\|%2e%2e))/g, '');
        if (sanitized.includes('/') || sanitized.includes('\\')) return null;

        return sanitized;
    }
};
