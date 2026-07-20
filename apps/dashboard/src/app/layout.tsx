import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import type { ReactNode } from "react";
import { DesktopBoundary } from "@/components/desktop-boundary";
import { Providers } from "@/components/providers";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "NTIP Management",
    template: "%s | NTIP",
  },
  description: "NTIP management plane for private network inventory and operations.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html
      lang="en"
      className={`${GeistSans.variable} ${GeistMono.variable}`}
      suppressHydrationWarning
    >
      <body>
        <Providers>
          <DesktopBoundary>{children}</DesktopBoundary>
        </Providers>
      </body>
    </html>
  );
}
