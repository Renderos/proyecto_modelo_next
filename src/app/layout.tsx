import type { Metadata } from "next";

import "./globals.css";
import Providers from "./Providers";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "Create Next App",
  description: "Generated by create next app",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning={true} data-qb-installed="true">
      <body>
        <div style={{
        backgroundImage: "url('https://t3.ftcdn.net/jpg/05/93/52/12/360_F_593521259_FTBggkMSTck8OKcMhZe9KZUkXFuVB3FG.jpg')",
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        minHeight: '100vh', 
      }}>
        <Providers>
          <Navbar />
          {children}
        </Providers>
        </div>
      </body>
    </html>
  );
}