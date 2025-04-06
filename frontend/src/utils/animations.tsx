import React, { ReactNode, useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import type { AnimationProps } from 'framer-motion';
import { motion } from 'framer-motion';

// Dynamically import motion components with SSR disabled
const AnimatePresence = dynamic(
  () => import('framer-motion').then((mod) => mod.AnimatePresence),
  { ssr: false }
);

// Fade In Animation Component
export const FadeIn: React.FC<{ children: ReactNode; delay?: number; duration?: number }> = ({
  children,
  delay = 0,
  duration = 0.5,
}) => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    transition={{ duration, delay }}
  >
    {children}
  </motion.div>
);

// Slide In Animation Component
export const SlideIn: React.FC<{
  children: ReactNode;
  direction?: 'left' | 'right' | 'up' | 'down';
  delay?: number;
  duration?: number;
}> = ({ children, direction = 'up', delay = 0, duration = 0.5 }) => {
  const directionMap = {
    left: { x: -50, y: 0 },
    right: { x: 50, y: 0 },
    up: { x: 0, y: 50 },
    down: { x: 0, y: -50 },
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: directionMap[direction].x, y: directionMap[direction].y }}
      animate={{ opacity: 1, x: 0, y: 0 }}
      exit={{ opacity: 0, x: directionMap[direction].x, y: directionMap[direction].y }}
      transition={{ duration, delay }}
    >
      {children}
    </motion.div>
  );
};

// Staggered Children Animation Component
export const StaggerChildren: React.FC<{
  children: ReactNode;
  staggerDelay?: number;
  containerDelay?: number;
}> = ({ children, staggerDelay = 0.1, containerDelay = 0 }) => {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ delay: containerDelay }}
    >
      {React.Children.map(children, (child, i) => (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: containerDelay + i * staggerDelay }}
        >
          {child}
        </motion.div>
      ))}
    </motion.div>
  );
};

// Scale Animation Component
export const ScaleIn: React.FC<{
  children: ReactNode;
  delay?: number;
  duration?: number;
}> = ({ children, delay = 0, duration = 0.5 }) => (
  <motion.div
    initial={{ opacity: 0, scale: 0.9 }}
    animate={{ opacity: 1, scale: 1 }}
    exit={{ opacity: 0, scale: 0.9 }}
    transition={{ duration, delay }}
  >
    {children}
  </motion.div>
);

// Hover Animation Component
export const HoverScale: React.FC<{
  children: ReactNode;
  scale?: number;
}> = ({ children, scale = 1.05 }) => (
  <motion.div whileHover={{ scale }} transition={{ duration: 0.2 }}>
    {children}
  </motion.div>
);

// Loading Spinner Animation
export const LoadingSpinner: React.FC<{
  size?: number;
  color?: string;
}> = ({ size = 40, color = '#3B82F6' }) => {
  const MotionDiv = motion.div;
  return (
    <MotionDiv
      style={{
        width: size,
        height: size,
        borderRadius: '50%',
        border: `4px solid ${color}`,
        borderTopColor: 'transparent',
        display: 'inline-block',
      }}
      animate={{ rotate: 360 }}
      transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
    />
  );
};

// Page Transition Component
export const PageTransition: React.FC<{
  children: ReactNode;
}> = ({ children }) => (
  <motion.div
    initial={{ opacity: 0 }}
    animate={{ opacity: 1 }}
    exit={{ opacity: 0 }}
    transition={{ duration: 0.3 }}
  >
    {children}
  </motion.div>
);

// Notification Animation Component
export const AnimatedNotification: React.FC<{
  children: ReactNode;
  isVisible: boolean;
}> = ({ children, isVisible }) => (
  <AnimatePresence>
    {isVisible && (
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -20 }}
        transition={{ duration: 0.3 }}
      >
        {children}
      </motion.div>
    )}
  </AnimatePresence>
);

// Pulse Animation Component
export const PulseAnimation: React.FC<{
  children: ReactNode;
}> = ({ children }) => (
  <motion.div
    animate={{
      scale: [1, 1.05, 1],
    }}
    transition={{
      duration: 2,
      repeat: Infinity,
      repeatType: 'loop',
    }}
  >
    {children}
  </motion.div>
);

// Appear on Scroll Component
export const AppearOnScroll: React.FC<{
  children: ReactNode;
}> = ({ children }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [hasAnimated, setHasAnimated] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !hasAnimated) {
          setIsVisible(true);
          setHasAnimated(true);
        }
      },
      { threshold: 0.1 }
    );

    const currentElement = document.getElementById('scroll-element');
    if (currentElement) {
      observer.observe(currentElement);
    }

    return () => {
      if (currentElement) {
        observer.unobserve(currentElement);
      }
    };
  }, [hasAnimated]);

  return (
    <div id="scroll-element">
      <AnimatePresence>
        {isVisible && (
          <motion.div
            initial={{ opacity: 0, y: 50 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            {children}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};