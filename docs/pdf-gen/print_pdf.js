const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
  try {
    const browser = await puppeteer.launch({
      executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
      headless: 'new'
    });
    const page = await browser.newPage();
    const fileUrl = 'file:///' + path.resolve('../project_report.html').replace(/\\/g, '/');
    console.log('Loading URL:', fileUrl);
    await page.goto(fileUrl, { waitUntil: 'networkidle0' });
    await page.pdf({
      path: '../project_report.pdf',
      format: 'A4',
      printBackground: true,
      margin: { top: '0', right: '0', bottom: '0', left: '0' }
    });
    console.log('PDF generated successfully');
    await browser.close();
  } catch (err) {
    console.error('Error generating PDF:', err);
    process.exit(1);
  }
})();
