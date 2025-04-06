import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { FaShieldAlt, FaList, FaHome, FaChartBar } from 'react-icons/fa';
import dynamic from 'next/dynamic';

// Dynamically import motion components with SSR disabled
const MotionDiv = dynamic(() => import('framer-motion').then(mod => mod.motion.div), { ssr: false });
const MotionNav = dynamic(() => import('framer-motion').then(mod => mod.motion.nav), { ssr: false });

const NavContent: React.FC<{
  isMounted: boolean;
  isActive: (path: string) => string;
  navItemVariants: any;
  logoVariants: any;
}> = ({ isMounted, isActive, navItemVariants, logoVariants }) => (
  <div className="container mx-auto px-4">
    <div className="flex items-center justify-between h-16">
      {isMounted ? (
        <MotionDiv
          className="flex items-center"
          whileHover="hover"
          variants={logoVariants}
        >
          <Link href="/" className="flex items-center">
            <FaShieldAlt className="h-8 w-8 mr-2" />
            <span className="font-bold text-xl">Website Security Scanner</span>
          </Link>
        </MotionDiv>
      ) : (
        <div className="flex items-center">
          <Link href="/" className="flex items-center">
            <FaShieldAlt className="h-8 w-8 mr-2" />
            <span className="font-bold text-xl">Website Security Scanner</span>
          </Link>
        </div>
      )}

      <div className="hidden md:block">
        <div className="ml-10 flex items-center space-x-4">
          {isMounted ? (
            <>
              <MotionDiv whileHover="hover" variants={navItemVariants}>
                <Link 
                  href="/" 
                  className={`px-3 py-2 rounded-md text-sm font-medium ${isActive('/')}`}
                >
                  <span className="flex items-center">
                    <FaHome className="mr-1" /> Home
                  </span>
                </Link>
              </MotionDiv>
              <MotionDiv whileHover="hover" variants={navItemVariants}>
                <Link 
                  href="/dashboard" 
                  className={`px-3 py-2 rounded-md text-sm font-medium ${isActive('/dashboard')}`}
                >
                  <span className="flex items-center">
                    <FaChartBar className="mr-1" /> Dashboard
                  </span>
                </Link>
              </MotionDiv>
              <MotionDiv whileHover="hover" variants={navItemVariants}>
                <Link 
                  href="/reports" 
                  className={`px-3 py-2 rounded-md text-sm font-medium ${isActive('/reports')}`}
                >
                  <span className="flex items-center">
                    <FaList className="mr-1" /> Reports
                  </span>
                </Link>
              </MotionDiv>
              {/* Add more navigation items here */}
            </>
          ) : (
            <Link 
              href="/" 
              className={`px-3 py-2 rounded-md text-sm font-medium ${isActive('/')}`}
            >
              <span className="flex items-center">
                <FaHome className="mr-1" /> Home
              </span>
            </Link>
          )}
        </div>
      </div>
    </div>
  </div>
);

const Navbar: React.FC = () => {
  const router = useRouter();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);
  
  const isActive = (path: string) => {
    return router.pathname === path ? 'text-white rounded-md' : 'text-white rounded-md';
  };

  const navItemVariants = {
    hover: { scale: 1.01, transition: { duration: 0.15 } }
  };

  const logoVariants = {
    hover: { scale: 1.01, transition: { duration: 0.15 } }
  };

  return (
    <nav className="bg-primary-600 text-white shadow-md">
      <NavContent 
        isMounted={isMounted}
        isActive={isActive}
        navItemVariants={navItemVariants}
        logoVariants={logoVariants}
      />
    </nav>
  );
};

export default Navbar;
