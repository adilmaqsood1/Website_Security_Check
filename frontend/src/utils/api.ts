import axios from 'axios';
import { toast } from 'react-toastify';

// Create an axios instance with custom configuration
const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  timeout: 30000, // 30 seconds timeout
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add a request interceptor
api.interceptors.request.use(
  (config) => {
    // You can add auth tokens here if needed in the future
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add a response interceptor
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    // Handle common errors
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      if (error.response.status === 401) {
        toast.error('Authentication required');
      } else if (error.response.status === 403) {
        toast.error('You do not have permission to perform this action');
      } else if (error.response.status === 404) {
        toast.error('Resource not found');
      } else if (error.response.status >= 500) {
        toast.error('Server error. Please try again later.');
      }
    } else if (error.request) {
      // The request was made but no response was received
      toast.error('No response from server. Please check your connection.');
    } else {
      // Something happened in setting up the request that triggered an Error
      toast.error('An error occurred. Please try again.');
    }
    return Promise.reject(error);
  }
);

export default api;