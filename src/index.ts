import 'dotenv/config'
import path from 'node:path'
import express, { type Request, type Response } from 'express'
import cookieParser from 'cookie-parser'
import {
  createKindeServerClient,
  GrantType,
  type SessionManager
} from '@kinde-oss/kinde-typescript-sdk'

const app = express()
app.use(cookieParser(process.env.COOKIE_SECRET))

const sessionManager = (req: Request, res: Response): SessionManager => ({
  async getSessionItem(key: string) {
    return req.signedCookies[key] ?? null
  },
  async setSessionItem(key: string, value: unknown) {
    res.cookie(key, value, {
      signed: true,
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 // 24 hours
    })
  },
  async removeSessionItem(key: string) {
    res.clearCookie(key)
  },
  async destroySession() {
    ;['user', 'access_token', 'refresh_token', 'id_token'].forEach((key) => {
      res.clearCookie(key)
    })
  }
})

const kindeClient = createKindeServerClient(GrantType.AUTHORIZATION_CODE, {
  authDomain: process.env.KINDE_DOMAIN,
  clientId: process.env.KINDE_CLIENT_ID,
  clientSecret: process.env.KINDE_CLIENT_SECRET,
  redirectURL: process.env.KINDE_REDIRECT_URI,
  logoutRedirectURL: process.env.KINDE_LOGOUT_REDIRECT_URI
})

app.get('/login', async (req, res) => {
  const loginUrl = await kindeClient.login(sessionManager(req, res))
  res.redirect(loginUrl.toString())
})

// not needed if you've disabled registrations -
// https://kinde.com/docs/authentication-and-access/disable-sign-up/
app.get('/register', async (req, res) => {
  const registerUrl = await kindeClient.register(sessionManager(req, res))
  res.redirect(registerUrl.toString())
})

app.get('/callback', async (req, res) => {
  const url = new URL(`${req.protocol}://${req.get('host')}${req.originalUrl}`)
  await kindeClient.handleRedirectToApp(sessionManager(req, res), url)
  res.redirect('/')
})

app.get('/logout', async (req, res) => {
  const logoutUrl = await kindeClient.logout(sessionManager(req, res))
  res.redirect(logoutUrl.toString())
})

app.get('*', async (req, res, next) => {
  if (['/login', '/register', '/callback', '/logout'].includes(req.path)) {
    return next()
  }
  if (!(await kindeClient.isAuthenticated(sessionManager(req, res)))) {
    return res.redirect('/login')
  }
  // do RBAC checks here

  return express.static(path.resolve(__dirname, '../docs/.vitepress/dist'), {
    extensions: ['html']
  })(req, res, next)
})

const port = Number(process.env.PORT) || 3000

app.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})

declare global {
  namespace NodeJS {
    interface ProcessEnv {
      KINDE_DOMAIN: string
      KINDE_CLIENT_ID: string
      KINDE_CLIENT_SECRET: string
      KINDE_REDIRECT_URI: string
      KINDE_LOGOUT_REDIRECT_URI: string
      COOKIE_SECRET: string
      PORT?: string
    }
  }
}
