import 'dotenv/config'
import { createVerifierApp } from '../apps/create-verifier-app.js'
import { serveApp } from './serve.js'

const { app } = createVerifierApp()
serveApp(app, 'Verifier', 8083)
