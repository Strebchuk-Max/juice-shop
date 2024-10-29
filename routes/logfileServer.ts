/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveLogFiles() {
    return ({ params }: Request, res: Response, next: NextFunction) => {
        const file = params.file

        // Resolve the absolute path of the logs directory and the requested file
        const logsDir = path.resolve('logs')
        const filePath = path.resolve(logsDir, file)

        // Check if the resolved path is within the logs directory
        if (!filePath.startsWith(logsDir)) {
            res.status(403)
            return next(new Error('Access denied: invalid file path!'))
        }

        // Check if the file exists and is readable before sending
        fs.access(filePath, fs.constants.R_OK, (err) => {
            if (err) {
                res.status(404).send('File not found')
            } else {
                res.sendFile(filePath)
            }
        })
    }
}
