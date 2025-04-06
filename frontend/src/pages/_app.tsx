import type { AppProps } from 'next/app';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import '@/styles/globals.css';
import { AnimationProvider } from '@/utils/AnimationContext';
import Layout from '@/components/Layout';

export default function App({ Component, pageProps }: AppProps) {
  return (
    <AnimationProvider>
      <Layout>
        <Component {...pageProps} />
      </Layout>
      <ToastContainer position="bottom-right" />
    </AnimationProvider>
  );
}
