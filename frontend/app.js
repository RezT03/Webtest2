document.getElementById('loginForm')?.addEventListener('submit', function (e) {
  e.preventDefault()
  const username = e.target.username.value
  const password = e.target.password.value
  fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
    .then(res => res.json())
    .then(data => {
      if (data.token) {
        localStorage.setItem('token', data.token)
        alert('Login successful')
      } else {
        alert('Login failed')
      }
    })
})

// Tambahkan token pada semua request lainnya seperti:
fetch('/api/scan/sqli', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authorization': localStorage.getItem('token') },
  body: JSON.stringify({ ... })
})

// frontend/app.js export grafik ke PDF
    
document.getElementById('exportGraphPDF').addEventListener('click', () => {
  html2canvas(document.getElementById('dosChart')).then(canvas => {
    const imgData = canvas.toDataURL('image/png')
    const pdf = new jsPDF()
    pdf.addImage(imgData, 'PNG', 10, 10, 180, 100)
    pdf.save('grafik-dos.pdf')
  })
})
