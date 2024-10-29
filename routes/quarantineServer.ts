/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveQuarantineFiles() {
    return ({ params }: Request, res: Response, next: NextFunction) => {
        const file = params.file

        // Resolve the absolute path of the quarantine directory and the requested file
        const quarantineDir = path.resolve('ftp/quarantine')
        const filePath = path.resolve(quarantineDir, file)

        // Ensure the resolved file path is within the quarantine directory to prevent path traversal
        if (!filePath.startsWith(quarantineDir) || file.includes('/')) {
            res.status(403)
            return next(new Error('Access denied: invalid file path!'))
        }

        // Check if the file exists and is readable
        fs.access(filePath, fs.constants.R_OK, (err) => {
            if (err) {
                res.status(404).send('File not found')
            } else {
                res.sendFile(filePath, (error) => {
                    if (error) {
                        next(new Error('Error sending file'))
                    }
                })
            }
        })
    }
}
