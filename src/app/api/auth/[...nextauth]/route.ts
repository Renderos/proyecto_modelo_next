import { connectDB } from "@/app/libs/mongodb";
import User from "@/app/models/user";
import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";

// Conexión con reintentos
const connectWithRetry = async (maxRetries = 3) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      await connectDB();
      return;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
};

// Búsqueda con timeout
const findUserWithTimeout = async (email: string) => {
  const timeout = new Promise((_, reject) => 
    setTimeout(() => reject(new Error("DB timeout")), 5000)
  );

  return Promise.race([
    User.findOne({ email }).select("+password"),
    timeout
  ]);
};

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        try {
          await connectWithRetry();
          const userFound = await findUserWithTimeout(credentials?.email || "");
          
          if (!userFound) throw new Error("User not found");
          
          const isValid = await bcrypt.compare(
            credentials!.password,
            userFound.password
          );
          if (!isValid) throw new Error("Invalid password");

          return {
            id: userFound._id.toString(),
            email: userFound.email,
            name: userFound.name
          };
        } catch (error) {
          console.error("Auth error:", error);
          return null;
        }
      }
    })
  ],
  pages: {
    signIn: "/login"
  },
  session: {
    strategy: "jwt",
    maxAge: 30 * 60 // 30 minutos
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) token.user = user;
      return token;
    },
    async session({ session, token }) {
      session.user = token.user as any;
      return session;
    }
  }
});

export { handler as GET, handler as POST };