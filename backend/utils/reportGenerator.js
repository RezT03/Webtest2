const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

function generatePDF(data, res, imageBase64 = null, language = 'id') {
  const doc = new PDFDocument();
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="report.pdf"');
  doc.pipe(res);

  // Logo
  const logoPath = path.join(__dirname, '../assets/logo.png');
  if (fs.existsSync(logoPath)) {
    doc.image(logoPath, 450, 15, { width: 100 });
  }

  doc.fontSize(18).text('Laporan Pengujian Keamanan Web', 50, 50, { underline: true })
  doc.moveDown();

  data.forEach((entry, index) => {
    doc.fontSize(12).text(`Pengujian #${index + 1}`);
    doc.text(`Jenis: ${entry.type}`);
    doc.text(`Target: ${entry.target}`);
    doc.text(`Berhasil: ${entry.success}`);
    doc.text(`Detail: ${entry.details}`);
    doc.text(`Waktu: ${entry.created_at}`);
    doc.moveDown();
  });

  if (imageBase64) {
    doc.addPage();
    doc.fontSize(16).text('Grafik Hasil Pengujian DoS', { align: 'center' });
    const imageBuffer = Buffer.from(imageBase64.split(',')[1], 'base64');
    doc.image(imageBuffer, { fit: [500, 300], align: 'center' });
  }

  // CVE section
  const cveFile = path.join(__dirname, '../cache/cve_results.json');
  if (fs.existsSync(cveFile)) {
    const cveData = JSON.parse(fs.readFileSync(cveFile));
    doc.addPage();
    doc.fontSize(16).text('Daftar Kerentanan (CVE)', { underline: true });
    doc.moveDown();
    cveData.results.forEach(block => {
      doc.fontSize(12).text(`Software: ${block.software}`);
      block.cves.forEach(item => {
        doc.text(`ID: ${item.id}`);
        doc.text(`CVSS: ${item.cvss}`);
        doc.text(`Ringkasan: ${language === 'en' ? item.summary_en : item.summary_id}`);
        doc.text(`Tanggal Publikasi: ${item.published}`);
        doc.moveDown();
      });
    });
  }

  doc.end();
}

module.exports = generatePDF;