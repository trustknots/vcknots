import 'dotenv/config'
import { createAuthzApp } from '../apps/create-authz-app.js'
import { serveApp } from './serve.js'

const { app } = createAuthzApp()
serveApp(app, 'Authz', 8082)
