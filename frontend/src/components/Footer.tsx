import React from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';

const MotionFooter = motion.footer;
const MotionDiv = motion.div;

const Footer: React.FC = () => {
  const linkVariants = {
    hover: { scale: 1.05, color: '#93c5fd', transition: { duration: 0.2 } }
  };

  return (
    <MotionFooter 
      className="bg-gray-800 text-white py-6"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: 0.3, duration: 0.5 }}
    >
      <div className="container mx-auto px-4">
        <div className="flex flex-col md:flex-row justify-between items-center">
          <MotionDiv 
            className="mb-4 md:mb-0"
            initial={{ y: 20, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ delay: 0.4 }}
          >
            <p className="text-sm">&copy; {new Date().getFullYear()} Website Security Scanner. All rights reserved.</p>
          </MotionDiv>
          
          <div className="flex space-x-4">
            <MotionDiv whileHover="hover" variants={linkVariants}>
              <Link href="/about" className="text-sm hover:text-primary-300 transition-colors duration-200">
                About
              </Link>
            </MotionDiv>
            <MotionDiv whileHover="hover" variants={linkVariants}>
              <Link href="/privacy" className="text-sm hover:text-primary-300 transition-colors duration-200">
                Privacy Policy
              </Link>
            </MotionDiv>
            <MotionDiv whileHover="hover" variants={linkVariants}>
              <Link href="/terms" className="text-sm hover:text-primary-300 transition-colors duration-200">
                Terms of Service
              </Link>
            </MotionDiv>
          </div>
        </div>
      </div>
    </MotionFooter>
  );
};

export default Footer;