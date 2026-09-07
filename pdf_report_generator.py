from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class EnterpriseReportGenerator:
    # (Existing methods...)
    
    @staticmethod
    def generate_pdf_report(scan_results: Dict[str, Any],
                            vulnerabilities: List[Vulnerability],
                            metadata: Dict[str, str],
                            output_filename: str = "security_report.pdf") -> str:
        """Generate professional enterprise PDF security report"""
        doc = SimpleDocTemplate(output_filename, pagesize=letter,
                                rightMargin=36, leftMargin=36,
                                topMargin=36, bottomMargin=36)
        story = []
        styles = getSampleStyleSheet()
        
        # Title Style
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=22,
            textColor=colors.HexColor('#FF6B35'),
            spaceAfter=12
        )
        
        story.append(Paragraph("🛡️ MHZALY Enterprise Security Report", title_style))
        story.append(Paragraph(f"<b>Asset:</b> {metadata.get('asset', 'Unknown')} | <b>Date:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 15))
        
        # Summary Table
        summary_data = [
            ['Severity', 'Count'],
            ['Critical', sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)],
            ['High', sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)],
            ['Medium', sum(1 for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM)],
            ['Low', sum(1 for v in vulnerabilities if v.severity == SeverityLevel.LOW)]
        ]
        
        t = Table(summary_data, colWidths=[200, 100])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1C2128')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 8),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#F6F8FA')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#D0D7DE'))
        ]))
        
        story.append(t)
        story.append(Spacer(1, 20))
        
        # Detailed Findings Section
        story.append(Paragraph("Detailed Vulnerability Findings", styles['Heading2']))
        story.append(Spacer(1, 10))
        
        for vuln in vulnerabilities:
            vuln_text = f"<b>{vuln.cve_id}</b> ({vuln.severity.name}) - Score: {vuln.cvss_score}<br/>{vuln.description[:200]}..."
            story.append(Paragraph(vuln_text, styles['Normal']))
            story.append(Spacer(1, 8))
            
        doc.build(story)
        return output_filename
