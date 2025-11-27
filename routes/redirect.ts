/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// Дозволені внутрішні хости (можеш змінити при потребі)
const allowedHosts = ['localhost', '127.0.0.1']

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string

    try {
      // Створюємо URL з базовим доменом
      const parsed = new URL(toUrl, 'http://localhost')

      const isRelative = toUrl.startsWith('/')
      const isAllowedHost = allowedHosts.includes(parsed.hostname)

      // Дозволяємо лише внутрішні переходи
      if (isRelative || isAllowedHost) {
        challengeUtils.solveIf(
          challenges.redirectCryptoCurrencyChallenge,
          () => {
            return (
              toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
                  toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
                  toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
            )
          }
        )

        challengeUtils.solveIf(
          challenges.redirectChallenge,
          () => { return isUnintendedRedirect(toUrl) }
        )

        // Безпечний редірект (парсимо тільки шлях і параметри)
        res.redirect(parsed.pathname + parsed.search); return
      }

      // Якщо URL небезпечний → блокуємо
      res.status(406)
      next(new Error('Blocked unsafe redirect to: ' + toUrl))
    } catch (e) {
      // Некоректний URL → також блокуємо
      res.status(406)
      next(new Error('Invalid redirect URL: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
