import { cert, initializeApp } from 'firebase-admin/app'
import { firestoreIssuerMetadataStore } from '@trustknots/google-cloud'
import { createServer } from './server.js'

// Reference:
// const vk = vcknots({
// Variable infrastructure points and spec group extension points
// providers: [kms() /*key operation*/, firestore() /* data store*/],
// Variable processing sequence points
// extensions: [trace()],
//   debug: process.env.NODE_ENV !== "production",
// });

// Initialize Firebase App
const firebaseApp = initializeApp({
  credential: cert({
    projectId: process.env.GOOGLE_PROJECT_ID!,
    privateKey: process.env.FIREBASE_PRIVATE_KEY!.replace(/\\n/g, '\n'),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL!,
  }),
})

// Create a server with Firestore Providers
createServer({
  providers: [
    firestoreIssuerMetadataStore({
      app: firebaseApp,
      databaseId: process.env.FIRESTORE_DATABASE_ID,
    }),
  ],
})
