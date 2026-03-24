import 'dotenv/config'
import { cert, initializeApp } from 'firebase-admin/app'
import { firestore } from '@trustknots/google-cloud'
import { createServer } from '@trustknots/server-core'

// Reference:
// const vk = vcknots({
// Variable infrastructure points and spec group extension points
// providers: [kms() /*key operation*/, firestore() /* data store*/],
// Variable processing sequence points
// extensions: [trace()],
//   debug: process.env.NODE_ENV !== "production",
// });

// Environment variables are required
const { GOOGLE_PROJECT_ID, FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL } = process.env
if (!GOOGLE_PROJECT_ID || !FIREBASE_PRIVATE_KEY || !FIREBASE_CLIENT_EMAIL) {
  throw new Error(
    'Missing Firebase env vars: GOOGLE_PROJECT_ID, FIREBASE_PRIVATE_KEY, FIREBASE_CLIENT_EMAIL'
  )
}

// Initialize Firebase App
const firebaseApp = initializeApp({
  credential: cert({
    projectId: GOOGLE_PROJECT_ID,
    privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    clientEmail: FIREBASE_CLIENT_EMAIL,
  }),
})

// Create a server with Firestore Providers
createServer({
  providers: [
    firestore({
      app: firebaseApp,
      databaseId: process.env.FIRESTORE_DATABASE_ID,
    }),
  ],
})
