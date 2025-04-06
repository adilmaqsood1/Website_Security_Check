"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/router";
import api from "@/utils/api";
import { Button } from "@mui/material";
import { toast } from "react-hot-toast";
import { LoadingSpinner, PulseAnimation } from "@/utils/animations";

// Loader Component
const Loader = () => <div className="text-center py-4">Loading...</div>;

// InProgressLoader Component
const InProgressLoader = () => (
  <div className="inline-flex items-center ml-2">
    <div className="animate-spin h-4 w-4 border-2 border-blue-500 rounded-full border-t-transparent"></div>
    <span className="ml-2 text-blue-500">In Progress</span>
  </div>
);

// ErrorMessage Component
const ErrorMessage = ({ message }: { message: string }) => (
  <div className="text-red-500 text-center">{message}</div>
);

// SeverityBadge Component
const SeverityBadge = ({ severity }: { severity: "critical" | "high" | "medium" | "low" | "info" }) => {
  const severityColors = {
    critical: "bg-red-700 text-white",
    high: "bg-red-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-green-500 text-white",
    info: "bg-blue-500 text-white",
  };
  return (
    <span className={`px-2 py-1 text-sm rounded ${severityColors[severity]}`}>
      {severity.toUpperCase()}
    </span>
  );
};

interface Scan {
  id: string;
  status: string;
  target: string;
  started_at: string;
  completed_at?: string;
  summary?: {
    scan_duration: number;
    total_vulnerabilities: number;
  };
}

interface Vulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
}

const ScanDetailsPage = () => {
  const router = useRouter();
  const { id } = router.query;
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch scan details
  const fetchScanData = useCallback(async () => {
    if (!id) return;
    
    try {
      setLoading(true);
      const [scanResponse, vulnerabilitiesResponse] = await Promise.all([
        api.get(`/security/scan/${id}`),
        api.get(`/security/scan/${id}/vulnerabilities`),
      ]);
      setScan(scanResponse.data);
      setVulnerabilities(vulnerabilitiesResponse.data);
      setError(null);
    } catch (err) {
      console.error("Error fetching scan details:", err);
      setError("Failed to load scan details. Please try again.");
      toast.error("Failed to load scan details");
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    fetchScanData();

    const interval = setInterval(() => {
      if (scan?.status === "pending" || scan?.status === "in_progress") {
        fetchScanData();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [fetchScanData, scan?.status]);

  const handleDownloadReport = async () => {
    try {
      const { generatePDFReport } = await import("@/utils/pdfGenerator");
  
      if (!id) {
        toast.error("Invalid scan ID");
        return;
      }
  
      toast("Fetching latest scan details...");
  
      const [scanResponse, vulnerabilitiesResponse] = await Promise.all([
        api.get(`/security/scan/${id}`),
        api.get(`/security/scan/${id}/vulnerabilities`),
      ]);
  
      const freshScan = scanResponse.data;
      const freshVulnerabilities = vulnerabilitiesResponse.data;
  
      if (!freshScan) {
        toast.error("Scan details not available.");
        return;
      }
  
      const pdfBlob = generatePDFReport(freshScan, freshVulnerabilities);
      const url = window.URL.createObjectURL(pdfBlob);
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `security_scan_${id}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
  
      toast.success("PDF Report downloaded successfully");
    } catch (err) {
      console.error("Error downloading report:", err);
      toast.error("Failed to download report");
    }
  };

  // Format date with time
  const formatDateTime = (dateString: string | undefined | null) => {
    if (!dateString) return "N/A";
    try {
      const date = new Date(dateString);
      // Check if date is valid
      if (isNaN(date.getTime())) return "N/A";
      return date.toLocaleString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch (error) {
      console.error("Error formatting date:", error, dateString);
      return "N/A";
    }
  };

  if (loading) return <Loader />;
  if (error) return <ErrorMessage message={error} />;

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold">Scan Details</h1>
      <div className="bg-white p-4 shadow-md rounded-lg mt-4">
        <p><strong>Target:</strong> {scan?.target}</p>
        <p>
          <strong>Status:</strong> 
          {scan?.status === "in_progress" ? (
            <span className="flex items-center">
              <span className="mr-2">In Progress</span>
              <InProgressLoader />
            </span>
          ) : scan?.status}
        </p>
        <p>
          <strong>Started At:</strong> 
          {scan?.started_at ? formatDateTime(scan.started_at) : "N/A"}
        </p>
        <p>
          <strong>Completed At:</strong> 
          {scan?.status === "in_progress" || scan?.status === "pending" ? (
            <span className="flex items-center">
              <span className="mr-2">In Progress</span>
              <InProgressLoader />
            </span>
          ) : (scan?.completed_at ? formatDateTime(scan.completed_at) : "N/A")}
        </p>
        <p><strong>Scan Duration:</strong> {scan?.summary?.scan_duration ? `${scan.summary.scan_duration.toFixed(2)} seconds` : "N/A"}</p>
        <p><strong>Total Vulnerabilities:</strong> {scan?.summary?.total_vulnerabilities || 0}</p>
        <Button className="mt-4" onClick={handleDownloadReport}>Download Report</Button>
      </div>

      <h2 className="text-xl font-semibold mt-6">Vulnerabilities</h2>
      <div className="mt-2">
        {loading ? (
          <div className="flex justify-center items-center py-8">
            <LoadingSpinner size={24} color="#3B82F6" />
            <span className="ml-3 text-blue-500">Loading vulnerabilities...</span>
          </div>
        ) : scan?.status === "in_progress" ? (
          <div className="flex justify-center items-center py-4">
            <PulseAnimation>
              <div className="flex items-center">
                <LoadingSpinner size={20} color="#3B82F6" />
                <span className="ml-3 text-blue-500">Scan in progress, vulnerabilities will appear here...</span>
              </div>
            </PulseAnimation>
          </div>
        ) : vulnerabilities.length === 0 ? (
          <p>No vulnerabilities found.</p>
        ) : (
          <ul>
            {vulnerabilities.map((vuln) => (
              <li key={vuln.id} className="border-b py-2">
                <p className="font-bold">{vuln.name}</p>
                <SeverityBadge severity={vuln.severity} />
                <p className="text-gray-600">{vuln.description}</p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default ScanDetailsPage;
