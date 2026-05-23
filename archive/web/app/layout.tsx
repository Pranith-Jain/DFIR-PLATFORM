import type { Metadata } from "next";
import { Inter, Poppins } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });
const poppins = Poppins({ weight: ["400", "500", "600", "700"], subsets: ["latin"], variable: "--font-poppins" });

export const metadata: Metadata = {
  title: "DFIR Platform - Free Security Tools",
  description: "Cybersecurity research, threat intelligence, and free DFIR tools — phishing email checker, exposure scanner, domain lookup, and detection engineering resources.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.variable} ${poppins.variable} font-sans min-h-screen bg-slate-950 text-slate-50`}>
        {children}
      </body>
    </html>
  );
}