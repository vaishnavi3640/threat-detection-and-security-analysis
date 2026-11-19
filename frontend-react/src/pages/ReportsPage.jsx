import { useEffect, useState } from 'react'
import { FileText, Download } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../api'
import '../components/shared.css'

export default function ReportsPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState({})

  useEffect(() => {
    api.listScans().then(r => setScans(r.data)).finally(() => setLoading(false))
  }, [])

  const handleGenerate = async (id) => {
    setGenerating(g => ({ ...g, [id]: true }))
    try {
      const r = await api.generateReport(id)
      toast.success('Report generated: ' + r.data.report_path)
    } catch {
      toast.error('Report generation failed')
    } finally {
      setGenerating(g => ({ ...g, [id]: false }))
    }
  }

  if (loading) return <div className="spinner" />

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><FileText size={26} /> Reports</h1>
        <p className="page-subtitle">Generate PDF security reports for any completed scan</p>
      </div>
      {scans.length === 0
        ? <div className="empty-state"><FileText size={40}/><h3>No scans available</h3><p>Run a scan first</p></div>
        : (
          <div className="card">
            <div className="table-wrap">
              <table>
                <thead><tr><th>Domain</th><th>Trust Score</th><th>Findings</th><th>Scan Date</th><th>Report</th></tr></thead>
                <tbody>
                  {scans.map(s => (
                    <tr key={s.scan_id}>
                      <td><span style={{ fontFamily:'JetBrains Mono', color:'var(--accent)' }}>{s.domain}</span></td>
                      <td><span style={{ color:'#22c55e', fontWeight:600 }}>{s.trust_score}</span></td>
                      <td>{s.total_findings}</td>
                      <td style={{ fontSize:12, color:'var(--text-muted)' }}>{new Date(s.scan_date).toLocaleDateString()}</td>
                      <td>
                        <button className="btn btn-primary" style={{ padding:'6px 14px', fontSize:12 }}
                          disabled={generating[s.scan_id]} onClick={() => handleGenerate(s.scan_id)}>
                          <Download size={13} /> {generating[s.scan_id] ? 'Generating…' : 'PDF Report'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )
      }
      <div className="alert alert-info" style={{ marginTop:16 }}>
        💡 PDF reports are saved to the <code>outputs/</code> folder in the backend directory.
      </div>
    </div>
  )
}
