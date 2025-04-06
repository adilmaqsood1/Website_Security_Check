import React, { useState, useEffect } from 'react';
import { toast } from 'react-toastify';
import { FaShieldAlt, FaSpinner, FaExclamationTriangle, FaInfoCircle } from 'react-icons/fa';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, Title } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';
import api from '@/utils/api';

// Register ChartJS components
ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

interface ScanSummary {
  total_scans: number;
  completed_scans: number;
  in_progress_scans: number;
  failed_scans: number;
  total_vulnerabilities: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  recent_scans: {
    id: string;
    url: string;
    scan_type: string;
    status: string;
    created_at: string;
    vulnerabilities_count: number;
  }[];
}

const Dashboard: React.FC = () => {
  const [summary, setSummary] = useState<ScanSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
    
    // Refresh dashboard data every 30 seconds
    const interval = setInterval(() => {
      fetchDashboardData();
    }, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      // Use the API client instead of axios directly
      const response = await api.get('/security/scans');
      
      // Process the data to create a summary
      const scans = response.data;
      const summary: ScanSummary = {
        total_scans: scans.length,
        completed_scans: scans.filter(s => s.status === 'completed').length,
        in_progress_scans: scans.filter(s => s.status === 'in_progress' || s.status === 'pending').length,
        failed_scans: scans.filter(s => s.status === 'failed' || s.status === 'cancelled').length,
        total_vulnerabilities: scans.reduce((total, scan) => {
          return total + (scan.summary?.total_vulnerabilities || 0);
        }, 0),
        severity_counts: {
          critical: scans.reduce((total, scan) => total + (scan.summary?.severity_counts?.critical || 0), 0),
          high: scans.reduce((total, scan) => total + (scan.summary?.severity_counts?.high || 0), 0),
          medium: scans.reduce((total, scan) => total + (scan.summary?.severity_counts?.medium || 0), 0),
          low: scans.reduce((total, scan) => total + (scan.summary?.severity_counts?.low || 0), 0),
          info: scans.reduce((total, scan) => total + (scan.summary?.severity_counts?.info || 0), 0),
        },
        recent_scans: scans
          .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
          .slice(0, 5)
          .map(scan => ({
            id: scan.id,
            url: scan.url,
            scan_type: scan.scan_type,
            status: scan.status,
            created_at: scan.created_at,
            vulnerabilities_count: scan.summary?.total_vulnerabilities || 0
          }))
      };
      
      setSummary(summary);
      setError(null);
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
      setError('Failed to load dashboard data. Please try again.');
      toast.error('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const severityChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [
      {
        data: summary ? [
          summary.severity_counts.critical,
          summary.severity_counts.high,
          summary.severity_counts.medium,
          summary.severity_counts.low,
          summary.severity_counts.info
        ] : [0, 0, 0, 0, 0],
        backgroundColor: [
          '#dc2626', // Critical - danger-600
          '#ef4444', // High - danger-500
          '#f59e0b', // Medium - warning-500
          '#fbbf24', // Low - warning-400
          '#0ea5e9', // Info - primary-500
        ],
        borderWidth: 1,
      },
    ],
  };

  const scanStatusChartData = {
    labels: ['Completed', 'In Progress', 'Failed'],
    datasets: [
      {
        data: summary ? [
          summary.completed_scans,
          summary.in_progress_scans,
          summary.failed_scans
        ] : [0, 0, 0],
        backgroundColor: [
          '#22c55e', // Completed - success-500
          '#0ea5e9', // In Progress - primary-500
          '#ef4444', // Failed - danger-500
        ],
        borderWidth: 1,
      },
    ],
  };

  if (loading && !summary) {
    return (
      <div className="flex justify-center items-center h-64">
        <FaSpinner className="animate-spin text-4xl text-primary-500" />
        <span className="ml-3 text-xl">Loading dashboard...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-danger-50 text-danger-700 p-4 rounded-md mb-6">
        {error}
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center mb-6">
        <FaShieldAlt className="text-primary-600 text-3xl mr-3" />
        <h1 className="text-3xl font-bold">Security Dashboard</h1>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold text-gray-700 mb-2">Total Scans</h2>
          <p className="text-3xl font-bold">{summary?.total_scans || 0}</p>
        </div>
        
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold text-gray-700 mb-2">Completed Scans</h2>
          <p className="text-3xl font-bold text-success-600">{summary?.completed_scans || 0}</p>
        </div>
        
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold text-gray-700 mb-2">In Progress</h2>
          <p className="text-3xl font-bold text-primary-600">{summary?.in_progress_scans || 0}</p>
        </div>
        
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-lg font-semibold text-gray-700 mb-2">Total Vulnerabilities</h2>
          <p className="text-3xl font-bold text-danger-600">{summary?.total_vulnerabilities || 0}</p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-xl font-semibold mb-4">Vulnerabilities by Severity</h2>
          <div className="h-64">
            <Pie data={severityChartData} options={{ maintainAspectRatio: false }} />
          </div>
        </div>
        
        <div className="bg-white rounded-lg shadow-md p-6">
          <h2 className="text-xl font-semibold mb-4">Scan Status</h2>
          <div className="h-64">
            <Pie data={scanStatusChartData} options={{ maintainAspectRatio: false }} />
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-xl font-semibold mb-4">Recent Scans</h2>
        
        {summary?.recent_scans && summary.recent_scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">URL</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Vulnerabilities</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {summary.recent_scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                      {scan.url.length > 40 ? `${scan.url.substring(0, 40)}...` : scan.url}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <span className="capitalize">{scan.scan_type}</span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      <span className={`px-2 py-1 inline-flex text-xs leading-5 font-semibold rounded-full ${
                        scan.status === 'completed' ? 'bg-success-100 text-success-800' :
                        scan.status === 'in_progress' ? 'bg-primary-100 text-primary-800' :
                        scan.status === 'pending' ? 'bg-gray-100 text-gray-800' :
                        'bg-danger-100 text-danger-800'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {scan.vulnerabilities_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-4">
            <p className="text-gray-500">No recent scans found</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;