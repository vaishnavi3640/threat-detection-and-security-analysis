import { useEffect, useState } from 'react'
import { History, ExternalLink } from 'lucide-react'
import { Link } from 'react-router-dom'
import api from '../api'
import '../components/shared.css'

export default function HistoryPage() {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getHistory().then(r => setHistory(r.data)).finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="spinner" />

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><History size={26} /> Scan History</h1>
        <p className="page-subtitle">All scanned websites and their trend data</p>
      </div>
      {history.length === 0
        ? <div className="empty-state"><History size={40}/><h3>No history yet</h3></div>
        : history.map(site => (
          <div key={site.url} className="card" style={{ marginBottom:16 }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
              <div>
                <div style={{ fontFamily:'JetBrains Mono', color:'var(--accent)', fontWeight:600, fontSize:16 }}>{site.domain}</div>
                <div style={{ fontSize:12, color:'var(--text-muted)', marginTop:2 }}>{site.scan_count} scan(s) · Last: {site.last_scan ? new Date(site.last_scan).toLocaleDateString() : '—'}</div>
              </div>
              <span style={{ fontWeight:700, fontSize:22, color: site.last_trust_score >= 70 ? '#22c55e' : site.last_trust_score >= 40 ? '#eab308' : '#ef4444' }}>
                {site.last_trust_score}
              </span>
            </div>
            <div className="table-wrap">
              <table>
                <thead><tr><th>#</th><th>Security</th><th>Privacy</th><th>Trust</th><th>Findings</th><th>Date</th><th></th></tr></thead>
                <tbody>
                  {site.scans.map((s,i) => (
                    <tr key={s.scan_id}>
                      <td style={{ color:'var(--text-muted)', fontSize:12 }}>#{i+1}</td>
                      <td style={{ color:'#3b82f6', fontWeight:600 }}>{s.security_score}</td>
                      <td style={{ color:'#a855f7', fontWeight:600 }}>{s.privacy_score}</td>
                      <td style={{ color:'#22c55e', fontWeight:600 }}>{s.trust_score}</td>
                      <td>{s.total_findings}</td>
                      <td style={{ fontSize:12, color:'var(--text-muted)' }}>{s.scan_date ? new Date(s.scan_date).toLocaleDateString() : '—'}</td>
                      <td>
                        <Link to={`/scan/${s.scan_id}`} className="btn btn-outline" style={{ padding:'4px 10px', fontSize:11 }}>
                          <ExternalLink size={11} /> View
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ))
      }
    </div>
  )
}
