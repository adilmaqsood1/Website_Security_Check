import React, { ReactNode, useEffect, useState } from 'react';
import Head from 'next/head';
import Navbar from './Navbar';
import Footer from './Footer';
import dynamic from 'next/dynamic';

// Dynamically import motion components with SSR disabled
const MotionMain = dynamic(
  () => import('framer-motion').then((mod) => {
    const { motion } = mod;
    return motion.main;
  }),
  { ssr: false }
);

interface LayoutProps {
  children: ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  return (
    <div className="min-h-screen flex flex-col">
      <Head>
        <title>Website Security Scanner</title>
        <meta name="description" content="Scan websites for security vulnerabilities" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link rel="alternate icon" href="/favicon.ico" type="image/x-icon" />
      </Head>
      
      <Navbar />
      
      {isMounted ? (
        <MotionMain 
          className="flex-grow container mx-auto px-4 py-8"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          {children}
        </MotionMain>
      ) : (
        <main className="flex-grow container mx-auto px-4 py-8">
          {children}
        </main>
      )}
      
      <Footer />
    </div>
  );
};

export default Layout;