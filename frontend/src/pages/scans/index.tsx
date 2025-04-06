import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { toast } from 'react-toastify';
import { FaExternalLinkAlt, FaDownload, FaSpinner, FaCheck, FaTimes, FaClock } from 'react-icons/fa';
import api from '@/utils/api';

interface Scan {
  id: string;
  url: string;
  scan_type: string;
  status: string;
  created_at: string;
  start_time: string | null;
  end_time: string | null;
  summary: {
    total_vulnerabilities: number;
    severity_counts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
  } | null;
}

const ScansPage: React.FC = () => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchScans();
    
    // Set up polling for in-progress scans
    const interval = setInterval(() => {
      if (scans.some(scan => scan.status === 'pending' || scan.status === 'in_progress')) {
        fetchScans();
      }
    }, 5000);
    
    return () => clearInterval(interval);
  }, [scans]);

  const fetchScans = async () => {
    try {
      setLoading(true);
      const response = await api.get('/security/scans');
      setScans(response.data);
      setError(null);
    } catch (err) {
      console.error('Error fetching scans:', err);
      setError('Failed to load scans. Please try again.');
      toast.error('Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = async (scanId: string) => {
    try {
      // Import the PDF generator function
      const { generatePDFReport } = await import('@/utils/pdfGenerator');
      
      // Fetch the scan data and vulnerabilities
      const scanResponse = await api.get(`/security/scan/${scanId}`);
      const vulnerabilitiesResponse = await api.get(`/security/scan/${scanId}/vulnerabilities`);
      
      // Generate the PDF report
      const pdfBlob = generatePDFReport(scanResponse.data, vulnerabilitiesResponse.data);
      
      // Create a download link
      const url = window.URL.createObjectURL(pdfBlob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `security_scan_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      toast.success('PDF Report downloaded successfully');
    } catch (err) {
      console.error('Error downloading report:', err);
      toast.error('Failed to download report');
    }
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      await api.post(`/security/scan/${scanId}/cancel`);
      toast.success('Scan cancelled successfully');
      fetchScans();
    } catch (err) {
      console.error('Error cancelling scan:', err);
      toast.error('Failed to cancel scan');
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <FaCheck className="text-success-500" />;
      case 'failed':
        return <FaTimes className="text-danger-500" />;
      case 'cancelled':
        return <FaTimes className="text-warning-500" />;
      case 'in_progress':
        return <FaSpinner className="text-primary-500 animate-spin" />;
      case 'pending':
        return <FaClock className="text-gray-500" />;
      default:
        return null;
    }
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-3xl font-bold">Security Scans</h1>
        <Link href="/" className="btn btn-primary">
          New Scan
        </Link>
      </div>

      {error && (
        <div className="bg-danger-50 text-danger-700 p-4 rounded-md mb-6">
          {error}
        </div>
      )}

      {loading && scans.length === 0 ? (
        <div className="flex justify-center items-center h-64">
          <FaSpinner className="animate-spin text-4xl text-primary-500" />
          <span className="ml-3 text-xl">Loading scans...</span>
        </div>
      ) : scans.length === 0 ? (
        <div className="bg-gray-50 rounded-lg p-8 text-center">
          <h3 className="text-xl font-medium text-gray-700 mb-2">No scans found</h3>
          <p className="text-gray-500 mb-4">Start your first security scan to see results here.</p>
          <Link href="/" className="btn btn-primary">
            Start a Scan
          </Link>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vulnerabilities</th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {scans.map((scan) => (
                <tr key={scan.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                    {scan.url.length > 40 ? `${scan.url.substring(0, 40)}...` : scan.url}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <span className="capitalize">{scan.scan_type}</span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div className="flex items-center">
                      {getStatusIcon(scan.status)}
                      <span className="ml-2 capitalize">{scan.status}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatDate(scan.created_at)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {scan.summary ? (
                      <div>
                        <span className="font-medium">{scan.summary.total_vulnerabilities}</span>
                        {scan.summary.severity_counts && (
                          <div className="flex space-x-1 mt-1">
                            {scan.summary.severity_counts.critical > 0 && (
                              <span className="badge badge-critical">{scan.summary.severity_counts.critical} Critical</span>
                            )}
                            {scan.summary.severity_counts.high > 0 && (
                              <span className="badge badge-high">{scan.summary.severity_counts.high} High</span>
                            )}
                          </div>
                        )}
                      </div>
                    ) : (
                      'N/A'
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <div className="flex justify-end space-x-2">
                      <Link 
                        href={`/scans/${scan.id}`}
                        className="text-primary-600 hover:text-primary-900"
                        title="View Details"
                      >
                        <FaExternalLinkAlt />
                      </Link>
                      
                      {scan.status === 'completed' && (
                        <button
                          onClick={() => handleDownloadReport(scan.id)}
                          className="text-primary-600 hover:text-primary-900"
                          title="Download Report"
                        >
                          <FaDownload />
                        </button>
                      )}
                      
                      {(scan.status === 'pending' || scan.status === 'in_progress') && (
                        <button
                          onClick={() => handleCancelScan(scan.id)}
                          className="text-danger-600 hover:text-danger-900"
                          title="Cancel Scan"
                        >
                          <FaTimes />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default ScansPage;