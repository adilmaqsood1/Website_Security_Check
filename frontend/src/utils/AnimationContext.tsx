import React, { createContext, useContext, ReactNode } from 'react';
import { motion, AnimatePresence, Variants } from 'framer-motion';

// Define animation context types
interface AnimationContextType {
  pageVariants: Variants;
  pageTransition: { type: string; ease: string; duration: number };
  cardVariants: Variants;
  listItemVariants: Variants;
  staggerDelay: number;
}

// Default animation settings
const defaultAnimationContext: AnimationContextType = {
  pageVariants: {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -20 },
  },
  pageTransition: {
    type: 'tween',
    ease: 'easeInOut',
    duration: 0.3,
  },
  cardVariants: {
    initial: { opacity: 0, scale: 0.95 },
    animate: { opacity: 1, scale: 1 },
    hover: { scale: 1.03 },
  },
  listItemVariants: {
    initial: { opacity: 0, x: -10 },
    animate: { opacity: 1, x: 0 },
    exit: { opacity: 0, x: 10 },
  },
  staggerDelay: 0.05,
};

// Create animation context
const AnimationContext = createContext<AnimationContextType>(defaultAnimationContext);

// Hook to use animation context
export const useAnimation = () => useContext(AnimationContext);

// Animation Provider
interface AnimationProviderProps {
  children: ReactNode;
}

export const AnimationProvider: React.FC<AnimationProviderProps> = ({ children }) => (
  <AnimationContext.Provider value={defaultAnimationContext}>
    {children}
  </AnimationContext.Provider>
);

// Animated page wrapper
export const AnimatedPage: React.FC<{ children: ReactNode }> = ({ children }) => {
  const { pageVariants, pageTransition } = useAnimation();

  return (
    <motion.div
      initial="initial"
      animate="animate"
      exit="exit"
      variants={pageVariants}
      transition={pageTransition}
    >
      {children}
    </motion.div>
  );
};

// Animated list with staggered children
export const AnimatedList: React.FC<{ children: ReactNode; className?: string }> = ({ children, className = '' }) => {
  const { staggerDelay } = useAnimation();

  return (
    <AnimatePresence>
      <div className={className}>
        {React.Children.map(children, (child, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ delay: i * staggerDelay, duration: 0.3 }}
          >
            {child}
          </motion.div>
        ))}
      </div>
    </AnimatePresence>
  );
};

// Animated card
export const AnimatedCard: React.FC<{ children: ReactNode; className?: string }> = ({ children, className = '' }) => {
  const { cardVariants } = useAnimation();

  return (
    <motion.div
      className={`card ${className}`}
      initial="initial"
      animate="animate"
      whileHover="hover"
      variants={cardVariants}
      style={{
        boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
      }}
    >
      {children}
    </motion.div>
  );
};
