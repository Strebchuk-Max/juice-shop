/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { decode } from 'jsonwebtoken'
import * as security from '../lib/insecurity'

async function retrieveUserList(req: Request, res: Response, next: NextFunction) {
    try {
        const users = await UserModel.findAll()

        res.json({
            status: 'success',
            data: users.map((user) => {
                const userToken = security.authenticatedUsers.tokenOf(user)
                let lastLoginTime: number | null = null
                if (userToken) {
                    const parsedToken = decode(userToken, { json: true })
                    lastLoginTime = parsedToken ? Math.floor(new Date((parsedToken?.iat ?? 0) * 1000).getTime()) : null
                }

                // Mask sensitive data such as password and TOTP secret
                return {
                    ...user.dataValues,
                    password: '*****', // Hide the password entirely, replacing it with a placeholder
                    totpSecret: '*****', // Replace with a placeholder for enhanced security
                    lastLoginTime
                }
            })
        })
    } catch (error) {
        next(error)
    }
}

export default () => retrieveUserList
