import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { FaShieldAlt, FaSearch } from 'react-icons/fa';
import { useRouter } from 'next/router';
import api from '@/utils/api';
import { motion } from 'framer-motion';
import { AnimatedPage, AnimatedCard, AnimatedList } from '@/utils/AnimationContext';

const Home: React.FC = () => {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [scanType, setScanType] = useState('quick');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!url) {
      toast.error('Please enter a URL to scan');
      return;
    }

    setIsLoading(true);

    try {
      const response = await api.post('/security/scan', {
        url: url,
        scan_type: scanType,
        options: {}
      });

      toast.success('Scan initiated successfully!');
      router.push(`/scans/${response.data.id}`);
    } catch (error) {
      console.error('Error starting scan:', error);
      toast.error('Failed to start scan. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AnimatedPage>
      <div className="flex flex-col items-center">
        <motion.div 
          className="text-center mb-10"
          initial={{ y: -20, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          transition={{ duration: 0.5 }}
        >
          <motion.div 
            className="flex justify-center mb-4"
            whileHover={{ rotate: [0, -5, 5, -5, 0] }}
            transition={{ duration: 0.5 }}
          >
            <FaShieldAlt className="text-primary-600 text-6xl" />
          </motion.div>
          <h1 className="text-4xl font-bold mb-2">Website Security Scanner</h1>
          <p className="text-xl text-gray-600 max-w-2xl mx-auto">
            Scan your website for security vulnerabilities and get detailed reports on potential issues.
          </p>
        </motion.div>

        <AnimatedCard className="w-full max-w-2xl bg-white rounded-lg shadow-md p-8">
          <h2 className="text-2xl font-semibold mb-6">Start a New Scan</h2>

          <form onSubmit={handleSubmit}>
            <motion.div 
              className="mb-6"
              initial={{ x: -20, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.2 }}
            >
              <label htmlFor="url" className="block font-medium mb-2">Website URL</label>
              <div className="relative">
                <input
                  type="url"
                  id="url"
                  className="w-full border border-gray-300 rounded-lg p-3 pl-10 focus:ring-primary-500 focus:border-primary-500"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  required
                />
                <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                  <FaSearch className="text-gray-400" />
                </div>
              </div>
            </motion.div>

            <motion.div 
              className="mb-6"
              initial={{ x: -20, opacity: 0 }}
              animate={{ x: 0, opacity: 1 }}
              transition={{ delay: 0.3 }}
            >
              <label className="block font-medium mb-2">Scan Type</label>
              <AnimatedList className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {['quick', 'full', 'custom'].map((type) => (
                  <div
                    key={type}
                    className={`border rounded-md p-4 cursor-pointer transition-colors ${
                      scanType === type
                        ? 'border-primary-500 bg-primary-50'
                        : 'border-gray-200 hover:border-primary-300'
                    }`}
                    onClick={() => setScanType(type)}
                  >
                    <div className="font-medium mb-1 capitalize">{type} Scan</div>
                    <div className="text-sm text-gray-600">
                      {type === 'quick'
                        ? 'Basic security checks on the main page only.'
                        : type === 'full'
                        ? 'Comprehensive security analysis of the entire site.'
                        : 'Select specific security checks to perform.'}
                    </div>
                  </div>
                ))}
              </AnimatedList>
            </motion.div>

            <motion.div
              initial={{ y: 20, opacity: 0 }}
              animate={{ y: 0, opacity: 1 }}
              transition={{ delay: 0.4 }}
              whileHover={{ scale: 1.03 }}
              whileTap={{ scale: 0.97 }}
            >
              <button
                type="submit"
                className="w-full bg-primary-600 hover:bg-primary-700 text-white font-semibold py-3 rounded-lg transition-all flex items-center justify-center"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Starting Scan...
                  </>
                ) : (
                  'Start Scan'
                )}
              </button>
            </motion.div>
          </form>
        </AnimatedCard>

        <motion.div 
          className="mt-12 text-center text-gray-600"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6 }}
        >
          <p>Our scanner checks for common vulnerabilities including XSS, SQL Injection, and more.</p>
        </motion.div>
      </div>
    </AnimatedPage>
  );
};

export default Home;
