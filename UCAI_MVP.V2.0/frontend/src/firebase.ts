import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getStorage } from "firebase/storage";

const firebaseConfig = {
  projectId: "gen-lang-client-0591533880",
  appId: "1:497422153083:web:1115f4e07699d693d6b9de",
  storageBucket: "gen-lang-client-0591533880.firebasestorage.app",
  apiKey: "AIzaSyBZNBjIN7zNCE2gShDFT5csad774r7hzOU",
  authDomain: "gen-lang-client-0591533880.firebaseapp.com",
  messagingSenderId: "497422153083"
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
