import 'dotenv/config'
import { createIssuerApp } from '../apps/create-issuer-app.js'
import { serveApp } from './serve.js'

const { app } = createIssuerApp()
serveApp(app, 'Issuer', 8081)
