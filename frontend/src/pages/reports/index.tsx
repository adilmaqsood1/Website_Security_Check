import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { toast } from 'react-toastify';
import { FaExternalLinkAlt, FaDownload, FaFilter, FaSort, FaSearch, FaInfo, FaShieldAlt, FaExclamationTriangle, FaExclamationCircle, FaInfoCircle, FaCheckCircle } from 'react-icons/fa';
import api from '@/utils/api';

interface Report {
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

const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [filteredReports, setFilteredReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [sortField, setSortField] = useState('created_at');
  const [sortDirection, setSortDirection] = useState('desc');

  useEffect(() => {
    fetchReports();
  }, []);

  useEffect(() => {
    // Apply filters and sorting whenever the reports or filter settings change
    let result = [...reports];
    
    // Apply status filter
    if (filterStatus !== 'all') {
      result = result.filter(report => report.status === filterStatus);
    }
    
    // Apply search term filter
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(report => 
        report.url.toLowerCase().includes(term) || 
        report.scan_type.toLowerCase().includes(term)
      );
    }
    
    // Apply sorting
    result.sort((a, b) => {
      let valueA, valueB;
      
      // Handle different field types
      if (sortField === 'created_at' || sortField === 'start_time' || sortField === 'end_time') {
        valueA = a[sortField] ? new Date(a[sortField] as string).getTime() : 0;
        valueB = b[sortField] ? new Date(b[sortField] as string).getTime() : 0;
      } else if (sortField === 'total_vulnerabilities') {
        valueA = a.summary?.total_vulnerabilities || 0;
        valueB = b.summary?.total_vulnerabilities || 0;
      } else {
        valueA = a[sortField as keyof Report] || '';
        valueB = b[sortField as keyof Report] || '';
      }
      
      // Apply sort direction
      if (sortDirection === 'asc') {
        return valueA > valueB ? 1 : -1;
      } else {
        return valueA < valueB ? 1 : -1;
      }
    });
    
    setFilteredReports(result);
  }, [reports, searchTerm, filterStatus, sortField, sortDirection]);

  const fetchReports = async () => {
    try {
      setLoading(true);
      const response = await api.get('/security/scans');
      setReports(response.data);
      setError(null);
    } catch (err) {
      console.error('Error fetching reports:', err);
      setError('Failed to load reports. Please try again.');
      toast.error('Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadReport = async (reportId: string) => {
    try {
      // Import the PDF generator function
      const { generatePDFReport } = await import('@/utils/pdfGenerator');
      
      // Fetch the scan data and vulnerabilities
      const scanResponse = await api.get(`/security/scan/${reportId}`);
      const vulnerabilitiesResponse = await api.get(`/security/scan/${reportId}/vulnerabilities`);
      
      // Generate the PDF report
      const pdfBlob = generatePDFReport(scanResponse.data, vulnerabilitiesResponse.data);
      
      // Create a download link
      const url = window.URL.createObjectURL(pdfBlob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `security_scan_${reportId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      toast.success('PDF Report downloaded successfully');
    } catch (err) {
      console.error('Error downloading report:', err);
      toast.error('Failed to download report');
    }
  };

  const handleSort = (field: string) => {
    if (sortField === field) {
      // Toggle sort direction if clicking the same field
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      // Set new sort field and default to descending
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const getSeverityTotal = (report: Report) => {
    if (!report.summary) return 0;
    const { critical, high, medium, low, info } = report.summary.severity_counts;
    return critical + high + medium + low + info;
  };

  const getSeverityColor = (severity: string, count: number) => {
    if (count === 0) return 'text-gray-400';
    
    switch (severity) {
      case 'critical': return 'text-red-600';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      case 'info': return 'text-gray-500';
      default: return 'text-gray-500';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return (
          <span className="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs flex items-center space-x-1">
            <FaCheckCircle className="text-xs" />
            <span>Completed</span>
          </span>
        );
      case 'in_progress':
        return (
          <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-xs flex items-center space-x-1 animate-pulse">
            <FaSpinner className="text-xs animate-spin" />
            <span>In Progress</span>
          </span>
        );
      case 'pending':
        return (
          <span className="px-2 py-1 bg-yellow-100 text-yellow-800 rounded-full text-xs flex items-center space-x-1">
            <FaInfoCircle className="text-xs" />
            <span>Pending</span>
          </span>
        );
      case 'failed':
        return (
          <span className="px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs flex items-center space-x-1">
            <FaExclamationCircle className="text-xs" />
            <span>Failed</span>
          </span>
        );
      case 'cancelled':
        return (
          <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded-full text-xs flex items-center space-x-1">
            <FaExclamationTriangle className="text-xs" />
            <span>Cancelled</span>
          </span>
        );
      default:
        return (
          <span className="px-2 py-1 bg-gray-100 text-gray-800 rounded-full text-xs flex items-center space-x-1">
            <FaInfoCircle className="text-xs" />
            <span>{status}</span>
          </span>
        );
    }
  };

  if (loading && reports.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center mb-6">
          <FaShieldAlt className="text-primary-600 text-3xl mr-3" />
          <h1 className="text-2xl font-bold text-gray-800">Security Reports</h1>
        </div>
        <div className="bg-white rounded-lg shadow-md p-12 mb-6 flex flex-col items-center justify-center">
          <div className="animate-spin rounded-full h-16 w-16 border-t-4 border-b-4 border-primary-600 mb-4"></div>
          <p className="text-gray-600 text-lg">Loading security reports...</p>
        </div>
      </div>
    );
  }

  if (error && reports.length === 0) {
    return (
      <div className="container mx-auto px-4 py-8">
        <div className="flex items-center mb-6">
          <FaShieldAlt className="text-primary-600 text-3xl mr-3" />
          <h1 className="text-2xl font-bold text-gray-800">Security Reports</h1>
        </div>
        <div className="bg-danger-50 border-l-4 border-danger-500 p-4 rounded-md" role="alert">
          <div className="flex">
            <div className="flex-shrink-0">
              <FaExclamationCircle className="h-5 w-5 text-danger-500" />
            </div>
            <div className="ml-3">
              <h3 className="text-lg font-medium text-danger-700">Error Loading Reports</h3>
              <p className="text-danger-600 mt-2">{error}</p>
              <button 
                onClick={() => fetchReports()} 
                className="mt-3 btn btn-danger inline-flex items-center space-x-2"
              >
                <span>Try Again</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="flex justify-between items-center mb-6">
        <div className="flex items-center">
          <FaShieldAlt className="text-primary-600 text-3xl mr-3" />
          <h1 className="text-2xl font-bold text-gray-800">Security Reports</h1>
        </div>
        <button 
          onClick={() => fetchReports()} 
          className="btn btn-primary flex items-center space-x-2"
        >
          <FaCheckCircle className="text-sm" />
          <span>Refresh Reports</span>
        </button>
      </div>

      <div className="bg-white rounded-lg shadow-md p-6 mb-6 border border-gray-100">
        <div className="flex flex-col md:flex-row justify-between mb-6 space-y-4 md:space-y-0 md:space-x-4">
          {/* Search input */}
          <div className="relative flex-grow max-w-md">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <FaSearch className="text-primary-500" />
            </div>
            <input
              type="text"
              placeholder="Search by URL or scan type..."
              className="input pl-10"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            {searchTerm && (
              <button 
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600"
                onClick={() => setSearchTerm('')}
                aria-label="Clear search"
              >
                ×
              </button>
            )}
          </div>

          {/* Filter controls */}
          <div className="flex space-x-4">
            {/* Status filter */}
            <div className="relative">
              <div className="flex items-center space-x-2">
                <div className="flex items-center space-x-1">
                  <FaFilter className="text-primary-500" />
                  <span className="text-sm font-medium text-gray-700">Status:</span>
                </div>
                <select
                  className="input py-1 pl-2 pr-8"
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                >
                  <option value="all">All Statuses</option>
                  <option value="completed">Completed</option>
                  <option value="in_progress">In Progress</option>
                  <option value="pending">Pending</option>
                  <option value="failed">Failed</option>
                  <option value="cancelled">Cancelled</option>
                </select>
              </div>
            </div>
            
            {/* Sort direction toggle */}
            <button 
              onClick={() => setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')}
              className="flex items-center space-x-1 px-3 py-2 bg-gray-100 hover:bg-gray-200 rounded-md transition-colors"
              title={`Currently sorting ${sortDirection === 'asc' ? 'ascending' : 'descending'}`}
            >
              <FaSort className="text-gray-600" />
              <span className="text-sm">{sortDirection === 'asc' ? 'Asc' : 'Desc'}</span>
            </button>
          </div>
        </div>

        {filteredReports.length === 0 ? (
          <div className="text-center py-12 px-4">
            <FaSearch className="mx-auto h-12 w-12 text-gray-300 mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No reports found</h3>
            <p className="text-gray-500 max-w-md mx-auto mb-6">
              {searchTerm || filterStatus !== 'all' ? 
                'No reports match your current search criteria. Try adjusting your filters or search term.' : 
                'No security reports have been generated yet. Start a new security scan to generate reports.'}
            </p>
            {searchTerm || filterStatus !== 'all' ? (
              <button 
                onClick={() => {
                  setSearchTerm('');
                  setFilterStatus('all');
                }}
                className="btn btn-secondary inline-flex items-center"
              >
                <FaFilter className="mr-2" />
                Clear Filters
              </button>
            ) : (
              <Link href="/" className="btn btn-primary inline-flex items-center">
                <FaShieldAlt className="mr-2" />
                Start New Scan
              </Link>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th 
                    scope="col" 
                    className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider cursor-pointer ${sortField === 'created_at' ? 'text-primary-700 bg-primary-50' : 'text-gray-500'}`}
                    onClick={() => handleSort('created_at')}
                  >
                    <div className="flex items-center">
                      <span>Date</span>
                      <FaSort className={`ml-1 ${sortField === 'created_at' ? 'text-primary-500' : 'text-gray-400'}`} />
                    </div>
                  </th>
                  <th 
                    scope="col" 
                    className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider cursor-pointer ${sortField === 'url' ? 'text-primary-700 bg-primary-50' : 'text-gray-500'}`}
                    onClick={() => handleSort('url')}
                  >
                    <div className="flex items-center">
                      <span>URL</span>
                      <FaSort className={`ml-1 ${sortField === 'url' ? 'text-primary-500' : 'text-gray-400'}`} />
                    </div>
                  </th>
                  <th 
                    scope="col" 
                    className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider cursor-pointer ${sortField === 'scan_type' ? 'text-primary-700 bg-primary-50' : 'text-gray-500'}`}
                    onClick={() => handleSort('scan_type')}
                  >
                    <div className="flex items-center">
                      <span>Scan Type</span>
                      <FaSort className={`ml-1 ${sortField === 'scan_type' ? 'text-primary-500' : 'text-gray-400'}`} />
                    </div>
                  </th>
                  <th 
                    scope="col" 
                    className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider cursor-pointer ${sortField === 'status' ? 'text-primary-700 bg-primary-50' : 'text-gray-500'}`}
                    onClick={() => handleSort('status')}
                  >
                    <div className="flex items-center">
                      <span>Status</span>
                      <FaSort className={`ml-1 ${sortField === 'status' ? 'text-primary-500' : 'text-gray-400'}`} />
                    </div>
                  </th>
                  <th 
                    scope="col" 
                    className={`px-6 py-3 text-left text-xs font-medium uppercase tracking-wider cursor-pointer ${sortField === 'total_vulnerabilities' ? 'text-primary-700 bg-primary-50' : 'text-gray-500'}`}
                    onClick={() => handleSort('total_vulnerabilities')}
                  >
                    <div className="flex items-center">
                      <span>Vulnerabilities</span>
                      <FaSort className={`ml-1 ${sortField === 'total_vulnerabilities' ? 'text-primary-500' : 'text-gray-400'}`} />
                    </div>
                  </th>
                  <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredReports.map((report) => (
                  <tr key={report.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {new Date(report.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 max-w-xs truncate">
                      {report.url}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {report.scan_type.charAt(0).toUpperCase() + report.scan_type.slice(1)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getStatusBadge(report.status)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {report.summary ? (
                        <div>
                          <div className="text-sm font-medium flex items-center">
                            <FaExclamationTriangle className={`mr-1 ${report.summary.total_vulnerabilities > 0 ? 'text-danger-500' : 'text-gray-400'}`} />
                            <span>{report.summary.total_vulnerabilities} total</span>
                          </div>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {report.summary.severity_counts.critical > 0 && (
                              <span className="badge badge-critical flex items-center">
                                <FaExclamationCircle className="mr-1 text-xs" />
                                {report.summary.severity_counts.critical} critical
                              </span>
                            )}
                            {report.summary.severity_counts.high > 0 && (
                              <span className="badge badge-high flex items-center">
                                <FaExclamationTriangle className="mr-1 text-xs" />
                                {report.summary.severity_counts.high} high
                              </span>
                            )}
                            {report.summary.severity_counts.medium > 0 && (
                              <span className="badge badge-medium flex items-center">
                                <FaExclamationTriangle className="mr-1 text-xs" />
                                {report.summary.severity_counts.medium} medium
                              </span>
                            )}
                          </div>
                        </div>
                      ) : (
                        <span className="text-gray-400 flex items-center">
                          <FaInfoCircle className="mr-1" />
                          N/A
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex justify-end space-x-2">
                        <Link 
                          href={`/scans/${report.id}`}
                          className="text-blue-600 hover:text-blue-900"
                          title="View Details"
                        >
                          <FaExternalLinkAlt />
                        </Link>
                        <button
                          onClick={() => handleDownloadReport(report.id)}
                          className="text-green-600 hover:text-green-900"
                          title="Download Report"
                          disabled={report.status !== 'completed'}
                        >
                          <FaDownload className={report.status !== 'completed' ? 'opacity-50 cursor-not-allowed' : ''} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="bg-primary-50 border border-primary-100 rounded-lg p-6 mb-6 shadow-sm">
        <div className="flex">
          <div className="flex-shrink-0">
            <FaInfoCircle className="h-6 w-6 text-primary-600" />
          </div>
          <div className="ml-4">
            <h3 className="text-lg font-medium text-primary-800 mb-2">About Security Reports</h3>
            <p className="text-primary-700 mb-3">
              Reports show a comprehensive view of all security scans performed on your websites. 
              You can filter, sort, and download detailed PDF reports for completed scans.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <div className="flex items-start">
                <FaFilter className="h-5 w-5 text-primary-500 mt-0.5 mr-2" />
                <div>
                  <h4 className="font-medium text-primary-800">Filter & Search</h4>
                  <p className="text-sm text-primary-600">Easily find reports by URL, scan type, or status</p>
                </div>
              </div>
              <div className="flex items-start">
                <FaSort className="h-5 w-5 text-primary-500 mt-0.5 mr-2" />
                <div>
                  <h4 className="font-medium text-primary-800">Sort Results</h4>
                  <p className="text-sm text-primary-600">Order reports by date, vulnerabilities, or other criteria</p>
                </div>
              </div>
              <div className="flex items-start">
                <FaDownload className="h-5 w-5 text-primary-500 mt-0.5 mr-2" />
                <div>
                  <h4 className="font-medium text-primary-800">Download Reports</h4>
                  <p className="text-sm text-primary-600">Export detailed PDF reports for completed scans</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReportsPage;