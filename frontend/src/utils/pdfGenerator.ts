import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface ScanSummary {
  total_vulnerabilities: number;
  severity_counts: SeverityCounts;
  scan_duration?: number;
  pages_scanned?: number;
}

interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: string;
  location: string;
  evidence?: string;
  remediation?: string;
  cwe_id?: string;
  cvss_score?: number;
}

interface ScanDetails {
  id: string;
  url?: string;
  target?: string; // Added target field as an alternative to url
  scan_type?: string;
  status: string;
  created_at?: string;
  started_at?: string; // Added started_at field as an alternative to start_time
  completed_at?: string; // Added completed_at field as an alternative to end_time
  start_time?: string | null;
  end_time?: string | null;
  summary: ScanSummary | null;
}

/**
 * Generate a PDF report from scan data
 * @param scan The scan details
 * @param vulnerabilities List of vulnerabilities found in the scan
 * @returns Blob containing the PDF document
 */
export const generatePDFReport = (scan: ScanDetails, vulnerabilities: Vulnerability[] = []): Blob => {
  // Initialize PDF document
  const doc = new jsPDF();
  const pageWidth = doc.internal.pageSize.getWidth();
  
  // Add report title
  doc.setFontSize(20);
  doc.setTextColor(0, 51, 102); // Dark blue color
  doc.text('Website Security Scan Report', pageWidth / 2, 20, { align: 'center' });
  
  // Add scan information
  doc.setFontSize(12);
  doc.setTextColor(0, 0, 0); // Black color
  doc.text(`URL: ${scan.url || scan.target || 'N/A'}`, 14, 35);
  doc.text(`Scan Type: ${scan.scan_type ? scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1) : 'N/A'}`, 14, 42);
  doc.text(`Status: ${scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}`, 14, 49);
  doc.text(`Date: ${scan.created_at ? new Date(scan.created_at).toLocaleString() : 'N/A'}`, 14, 56);
  
  // Handle different time field names
  const startTimeValue = scan.start_time || scan.started_at;
  const endTimeValue = scan.end_time || scan.completed_at;
  
  if (startTimeValue && endTimeValue) {
    const startTime = new Date(startTimeValue);
    const endTime = new Date(endTimeValue);
    doc.text(`Duration: ${((endTime.getTime() - startTime.getTime()) / 1000 / 60).toFixed(2)} minutes`, 14, 63);
  }
  
  // Add summary section
  doc.setFontSize(16);
  doc.setTextColor(0, 51, 102); // Dark blue color
  doc.text('Summary', 14, 75);
  
  if (scan.summary) {
    doc.setFontSize(12);
    doc.setTextColor(0, 0, 0); // Black color
    doc.text(`Total Vulnerabilities: ${scan.summary.total_vulnerabilities}`, 14, 85);
    
    // Add severity counts
    if (scan.summary.severity_counts) {
      const severityCounts = scan.summary.severity_counts;
      
      // Create a table for severity counts
      autoTable(doc, {
        startY: 95,
        head: [['Severity', 'Count']],
        body: [
          ['Critical', severityCounts.critical.toString()],
          ['High', severityCounts.high.toString()],
          ['Medium', severityCounts.medium.toString()],
          ['Low', severityCounts.low.toString()],
          ['Info', severityCounts.info.toString()]
        ],
        theme: 'striped',
        headStyles: { fillColor: [0, 51, 102] },
        columnStyles: {
          0: { cellWidth: 40 },
          1: { cellWidth: 40, halign: 'center' }
        }
      });
    }
  }
  
  // Add vulnerabilities section if there are any
  if (vulnerabilities.length > 0) {
    // Get the position after the last table or use default value
    const currentY = (doc as any).previousAutoTable ?(doc as any).previousAutoTable.finalY + 15 : 150;
    
    doc.setFontSize(16);
    doc.setTextColor(0, 51, 102); // Dark blue color
    doc.text('Vulnerabilities', 14, currentY);
    
    // Create a table for vulnerabilities
    const tableRows = vulnerabilities.map(vuln => [
      vuln.name,
      vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1),
      vuln.location,
      vuln.description.length > 50 ? vuln.description.substring(0, 50) + '...' : vuln.description
    ]);
    
    autoTable(doc, {
      startY: currentY + 10,
      head: [['Name', 'Severity', 'Location', 'Description']],
      body: tableRows,
      theme: 'striped',
      headStyles: { fillColor: [0, 51, 102] },
      columnStyles: {
        0: { cellWidth: 40 },
        1: { cellWidth: 30 },
        2: { cellWidth: 40 },
        3: { cellWidth: 'auto' }
      },
      didDrawPage: (data) => {
        // Add page number at the bottom
        const pageNumber = doc.getNumberOfPages();
        doc.setFontSize(10);
        doc.text(`Page ${pageNumber}`, pageWidth - 20, doc.internal.pageSize.getHeight() - 10);
      }
    });
    
    // Add detailed vulnerability information
    vulnerabilities.forEach((vuln, index) => {
      doc.addPage();
      
      // Add page number
      const pageNumber = doc.getNumberOfPages();
      doc.setFontSize(10);
      doc.text(`Page ${pageNumber}`, pageWidth - 20, doc.internal.pageSize.getHeight() - 10);
      
      // Add vulnerability details
      doc.setFontSize(16);
      doc.setTextColor(0, 51, 102); // Dark blue color
      doc.text(`Vulnerability #${index + 1}: ${vuln.name}`, 14, 20);
      
      doc.setFontSize(12);
      doc.setTextColor(0, 0, 0); // Black color
      doc.text(`Severity: ${vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)}`, 14, 30);
      doc.text(`Location: ${vuln.location}`, 14, 37);
      
      if (vuln.cwe_id) {
        doc.text(`CWE ID: ${vuln.cwe_id}`, 14, 44);
      }
      
      if (vuln.cvss_score) {
        doc.text(`CVSS Score: ${vuln.cvss_score}`, 14, 51);
      }
      
      // Description with word wrap
      doc.setFontSize(12);
      doc.text('Description:', 14, 58);
      const splitDescription = doc.splitTextToSize(vuln.description, pageWidth - 28);
      doc.text(splitDescription, 14, 65);
      
      let currentYPosition = 65 + (splitDescription.length * 7);
      
      // Evidence with word wrap if available
      if (vuln.evidence) {
        doc.text('Evidence:', 14, currentYPosition);
        const splitEvidence = doc.splitTextToSize(vuln.evidence, pageWidth - 28);
        doc.text(splitEvidence, 14, currentYPosition + 7);
        currentYPosition += 7 + (splitEvidence.length * 7);
      }
      
      // Enhanced remediation section with structured format
      if (vuln.remediation) {
        // Check if we need to add a new page for remediation section
        const pageHeight = doc.internal.pageSize.getHeight();
        if (currentYPosition > pageHeight - 60) { // Leave enough space for heading and initial content
          doc.addPage();
          // Add page number
          const pageNumber = doc.getNumberOfPages();
          doc.setFontSize(10);
          doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
          currentYPosition = 20; // Reset position to top of new page
        }
        
        // Main remediation heading
        doc.setFontSize(14);
        doc.setTextColor(0, 51, 102); // Dark blue color
        doc.text('Remediation:', 14, currentYPosition);
        currentYPosition += 10;
        
        // Reset to normal text style
        doc.setFontSize(12);
        doc.setTextColor(0, 0, 0); // Black color
        
        // Parse the remediation text to identify sections and clean markdown formatting
        let remediationText = vuln.remediation;
        
        // Remove all markdown header formatting (# through ####)
        remediationText = remediationText.replace(/^#{1,4}\s+/gm, '');
        
        // Clean up other markdown formatting
        remediationText = remediationText
          // Bold text (** or __)
          .replace(/\*\*([^*]+)\*\*/g, '$1')
          .replace(/__([^_]+)__/g, '$1')
          // Italic text (* or _)
          .replace(/\*([^*]+)\*/g, '$1')
          .replace(/_([^_]+)_/g, '$1')
          // Strikethrough text (~~)
          .replace(/~~([^~]+)~~/g, '$1')
          // Inline code (`)
          .replace(/`([^`]+)`/g, '$1')
          // Bullet points
          .replace(/^\s*[\*\-\+]\s+/gm, '• ')
          // Numbered lists (keep numbers but standardize format)
          .replace(/^\s*\d+\.\s+/gm, (match) => match);
        
        // Check if the remediation text contains structured sections
        if (remediationText.includes('1. Importance of Fixing') || remediationText.includes('Importance of Fixing')) {
          // For structured remediation format - remove markdown headers and clean up formatting
          
          // Split by section numbers (1., 2., etc.)
          const sections = remediationText.split(/\d+\.\s+/);
          
          // If the split didn't work well (only one section), try another approach
          if (sections.length <= 1) {
            // Try splitting by newline followed by a number and period
            const altSections = remediationText.split(/\n\d+\.\s+/);
            if (altSections.length > 1) {
              // Use this split instead
              sections.length = 0; // Clear the array
              altSections.forEach(section => sections.push(section));
            }
          }
          
          let sectionY = currentYPosition;
          const marginBottom = 20; // Space to reserve at bottom of page
          
          // Process each section after the split (skip the first empty element if exists)
          for (let i = 0; i < sections.length; i++) {
            if (sections[i].trim() === '') continue;
            
            // Extract section title and content
            const sectionParts = sections[i].split('\n');
            // Clean up any remaining markdown formatting from section title
            const sectionTitle = sectionParts[0].trim().replace(/^#+\s*/g, '');
            const sectionContent = sectionParts.slice(1).join('\n').trim();
            
            // Check if we need to add a new page before starting a new section
            if (sectionY > pageHeight - 40) { // Leave space for title and some content
              doc.addPage();
              // Add page number
              const pageNumber = doc.getNumberOfPages();
              doc.setFontSize(10);
              doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
              sectionY = 20; // Reset position to top of new page
            }
            
            // Add section title with bold styling
            doc.setFont('helvetica', 'bold');
            doc.text(sectionTitle, 14, sectionY);
            doc.setFont('helvetica', 'normal');
            sectionY += 7;
            
            // Add section content with proper formatting
            const splitContent = doc.splitTextToSize(sectionContent, pageWidth - 28);
            
            // Check if content will fit on current page
            const contentHeight = splitContent.length * 7;
            if (sectionY + contentHeight > pageHeight - marginBottom) {
              // Content won't fit on current page
              // Calculate how many lines will fit on current page
              const availableHeight = pageHeight - marginBottom - sectionY;
              const linesPerPage = Math.floor(availableHeight / 7);
              
              if (linesPerPage > 0) {
                // Add as many lines as will fit on current page
                const firstPageLines = splitContent.slice(0, linesPerPage);
                doc.text(firstPageLines, 14, sectionY);
              }
              
              // Add a new page for remaining content
              doc.addPage();
              // Add page number
              const pageNumber = doc.getNumberOfPages();
              doc.setFontSize(10);
              doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
              doc.setFontSize(12);
              
              // Continue with remaining content on new page
              const remainingLines = splitContent.slice(linesPerPage > 0 ? linesPerPage : 0);
              if (remainingLines.length > 0) {
                sectionY = 20; // Reset position to top of new page
                doc.text(remainingLines, 14, sectionY);
                sectionY += remainingLines.length * 7 + 10;
              } else {
                sectionY = 20; // Reset position to top of new page
              }
            } else {
              // Content fits on current page
              doc.text(splitContent, 14, sectionY);
              sectionY += contentHeight + 10;
            }
            
            // Handle code examples with special formatting
            if (sectionContent.includes('```')) {
              // Improved code block handling
              // Match code blocks with regex to properly capture content between backticks
              const codeBlockRegex = /```(?:\w*)\n([\s\S]*?)```/g;
              let lastIndex = 0;
              let contentY = sectionY;
              let match;
              
              // Process the content by finding all code blocks and handling text between them
              while ((match = codeBlockRegex.exec(sectionContent)) !== null) {
                // Handle text before the code block
                const textBeforeCode = sectionContent.substring(lastIndex, match.index).trim();
                if (textBeforeCode) {
                  const splitRegular = doc.splitTextToSize(textBeforeCode, pageWidth - 28);
                  
                  // Check if content will fit on current page
                  if (contentY + (splitRegular.length * 7) > pageHeight - marginBottom) {
                    // Add a new page
                    doc.addPage();
                    // Add page number
                    const pageNumber = doc.getNumberOfPages();
                    doc.setFontSize(10);
                    doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
                    doc.setFontSize(12);
                    contentY = 20; // Reset position to top of new page
                  }
                  
                  doc.text(splitRegular, 14, contentY);
                  contentY += splitRegular.length * 7 + 5; // Add a small gap
                }
                
                // Handle the code block
                const codeText = match[1].trim();
                if (codeText) {
                  const splitCode = doc.splitTextToSize(codeText, pageWidth - 40);
                  const codeHeight = splitCode.length * 7 + 10;
                  
                  // Check if code block will fit on current page
                  if (contentY + codeHeight > pageHeight - marginBottom) {
                    // Add a new page
                    doc.addPage();
                    // Add page number
                    const pageNumber = doc.getNumberOfPages();
                    doc.setFontSize(10);
                    doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
                    doc.setFontSize(12);
                    contentY = 20; // Reset position to top of new page
                  }
                  
                  // Draw a light gray background for code
                  doc.setFillColor(240, 240, 240);
                  doc.rect(14, contentY - 5, pageWidth - 28, codeHeight, 'F');
                  
                  // Add the code with monospace font
                  doc.setFont('courier', 'normal');
                  doc.text(splitCode, 20, contentY);
                  doc.setFont('helvetica', 'normal');
                  contentY += codeHeight + 5; // Add a small gap
                }
                
                lastIndex = match.index + match[0].length;
              }
              
              // Handle any remaining text after the last code block
              const textAfterLastCode = sectionContent.substring(lastIndex).trim();
              if (textAfterLastCode) {
                const splitRegular = doc.splitTextToSize(textAfterLastCode, pageWidth - 28);
                
                // Check if content will fit on current page
                if (contentY + (splitRegular.length * 7) > pageHeight - marginBottom) {
                  // Add a new page
                  doc.addPage();
                  // Add page number
                  const pageNumber = doc.getNumberOfPages();
                  doc.setFontSize(10);
                  doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
                  doc.setFontSize(12);
                  contentY = 20; // Reset position to top of new page
                }
                
                doc.text(splitRegular, 14, contentY);
                contentY += splitRegular.length * 7;
              }
              sectionY = contentY + 10;
            }
          }
          
          currentYPosition = sectionY;
        } else {
          // For simple unstructured remediation text
          // Clean up any markdown formatting from unstructured text
          remediationText = remediationText.replace(/^###\s+/gm, '');
          remediationText = remediationText.replace(/^####\s+/gm, '');
          remediationText = remediationText.replace(/^#\s+/gm, '');
          
          // Clean up other markdown formatting for unstructured text
          remediationText = remediationText
            // Bold text (** or __)
            .replace(/\*\*([^*]+)\*\*/g, '$1')
            .replace(/__([^_]+)__/g, '$1')
            // Italic text (* or _)
            .replace(/\*([^*]+)\*/g, '$1')
            .replace(/_([^_]+)_/g, '$1')
            // Strikethrough text (~~)
            .replace(/~~([^~]+)~~/g, '$1')
            // Inline code (`)
            .replace(/`([^`]+)`/g, '$1')
            // Bullet points
            .replace(/^\s*[\*\-\+]\s+/gm, '• ')
            // Numbered lists (keep numbers but standardize format)
            .replace(/^\s*\d+\.\s+/gm, (match) => match);
          
          // Handle code blocks in unstructured text
          if (remediationText.includes('```')) {
            // Use the same improved code block handling as in structured sections
            const codeBlockRegex = /```(?:\w*)\n([\s\S]*?)```/g;
            let lastIndex = 0;
            let contentY = currentYPosition;
            let match;
            let processedText = '';
            
            // Process the content by finding all code blocks and handling text between them
            while ((match = codeBlockRegex.exec(remediationText)) !== null) {
              // Add text before the code block to processed text
              processedText += remediationText.substring(lastIndex, match.index);
              
              // Handle the code block
              const codeText = match[1].trim();
              if (codeText) {
                // Add a new page if needed
                if (contentY > pageHeight - 60) {
                  doc.addPage();
                  // Add page number
                  const pageNumber = doc.getNumberOfPages();
                  doc.setFontSize(10);
                  doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
                  doc.setFontSize(12);
                  contentY = 20; // Reset position to top of new page
                }
                
                // Handle text before code block
                const textBeforeCode = remediationText.substring(lastIndex, match.index).trim();
                if (textBeforeCode) {
                  const splitRegular = doc.splitTextToSize(textBeforeCode, pageWidth - 28);
                  doc.text(splitRegular, 14, contentY);
                  contentY += splitRegular.length * 7 + 5; // Add a small gap
                }
                
                const splitCode = doc.splitTextToSize(codeText, pageWidth - 40);
                const codeHeight = splitCode.length * 7 + 10;
                
                // Check if code block will fit on current page
                if (contentY + codeHeight > pageHeight - 20) {
                  // Add a new page
                  doc.addPage();
                  // Add page number
                  const pageNumber = doc.getNumberOfPages();
                  doc.setFontSize(10);
                  doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
                  doc.setFontSize(12);
                  contentY = 20; // Reset position to top of new page
                }
                
                // Draw a light gray background for code
                doc.setFillColor(240, 240, 240);
                doc.rect(14, contentY - 5, pageWidth - 28, codeHeight, 'F');
                
                // Add the code with monospace font
                doc.setFont('courier', 'normal');
                doc.text(splitCode, 20, contentY);
                doc.setFont('helvetica', 'normal');
                contentY += codeHeight + 5; // Add a small gap
              }
              
              lastIndex = match.index + match[0].length;
            }
            
            // Handle any remaining text after the last code block
            const textAfterLastCode = remediationText.substring(lastIndex).trim();
            if (textAfterLastCode) {
              const splitRegular = doc.splitTextToSize(textAfterLastCode, pageWidth - 28);
              
              // Check if content will fit on current page
              if (contentY + (splitRegular.length * 7) > pageHeight - 20) {
                // Add a new page
                doc.addPage();
                // Add page number
                const pageNumber = doc.getNumberOfPages();
                doc.setFontSize(10);
                doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
                doc.setFontSize(12);
                contentY = 20; // Reset position to top of new page
              }
              
              doc.text(splitRegular, 14, contentY);
              contentY += splitRegular.length * 7;
            }
            
            currentYPosition = contentY;
          } else {
            // No code blocks, handle as regular text
            const splitRemediation = doc.splitTextToSize(remediationText, pageWidth - 28);
            const remediationHeight = splitRemediation.length * 7;
            
            // Check if remediation text will fit on current page
            if (currentYPosition + remediationHeight > pageHeight - 20) {
              // Calculate how many lines will fit on current page
              const availableHeight = pageHeight - 20 - currentYPosition;
              const linesPerPage = Math.floor(availableHeight / 7);
              
              if (linesPerPage > 0) {
                // Add as many lines as will fit on current page
                const firstPageLines = splitRemediation.slice(0, linesPerPage);
                doc.text(firstPageLines, 14, currentYPosition);
              }
              
              // Add a new page for remaining content
              doc.addPage();
              // Add page number
              const pageNumber = doc.getNumberOfPages();
              doc.setFontSize(10);
              doc.text(`Page ${pageNumber}`, pageWidth - 20, pageHeight - 10);
              doc.setFontSize(12);
              
              // Continue with remaining content on new page
              const remainingLines = splitRemediation.slice(linesPerPage > 0 ? linesPerPage : 0);
              if (remainingLines.length > 0) {
                currentYPosition = 20; // Reset position to top of new page
                doc.text(remainingLines, 14, currentYPosition);
                currentYPosition += remainingLines.length * 7;
              } else {
                currentYPosition = 20; // Reset position to top of new page
              }
            } else {
              // Content fits on current page
              doc.text(splitRemediation, 14, currentYPosition);
              currentYPosition += remediationHeight;
            }
          }
        }
      }
    });
  }
  
  // Add footer with generation date
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100); // Gray color
    doc.text(`Report generated on ${new Date().toLocaleString()}`, 14, doc.internal.pageSize.getHeight() - 10);
  }
  
  // Return the PDF as a blob
  return doc.output('blob');
};