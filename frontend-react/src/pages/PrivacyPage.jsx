import { useEffect, useState } from 'react'
import { Eye } from 'lucide-react'
import api from '../api'
import '../components/shared.css'

export default function PrivacyPage() {
  const [scans, setScans] = useState([])
  const [selected, setSelected] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.listScans().then(r => {
      setScans(r.data)
      if (r.data.length) setSelected(r.data[0].scan_id)
    }).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (selected) api.getFindings(selected, 'privacy').then(r => setFindings(r.data))
  }, [selected])

  if (loading) return <div className="spinner" />

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><Eye size={26} /> Privacy Analysis</h1>
        <p className="page-subtitle">Tracker detection, 3rd-party requests &amp; privacy policy checks</p>
      </div>
      {scans.length === 0
        ? <div className="empty-state"><Eye size={40}/><h3>No scans available</h3></div>
        : (
          <>
            <div style={{ marginBottom:20 }}>
              <label style={{ color:'var(--text-sec)', fontSize:13, marginRight:10 }}>Select Scan:</label>
              <select style={{ background:'var(--bg-hover)', border:'1px solid var(--border)', color:'var(--text-prim)', padding:'8px 12px', borderRadius:8, fontSize:13 }}
                value={selected} onChange={e => setSelected(Number(e.target.value))}>
                {scans.map(s => <option key={s.scan_id} value={s.scan_id}>{s.domain} — {new Date(s.scan_date).toLocaleDateString()}</option>)}
              </select>
            </div>
            <div className="card">
              <h3 className="card-title">Privacy Findings ({findings.length})</h3>
              {findings.length === 0
                ? <div className="empty-state"><h3>No privacy findings for this scan</h3></div>
                : findings.map(f => (
                  <div key={f.id} className="finding-card">
                    <div className="finding-header">
                      <div>
                        <div className="finding-name">{f.finding_name}</div>
                        <div className="finding-meta">Confidence: {f.confidence}</div>
                      </div>
                      <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                    </div>
                    {f.evidence && <div className="finding-section"><div className="finding-section-label">Evidence</div><div className="finding-evidence">{f.evidence}</div></div>}
                    {f.recommendation && <div className="finding-section"><div className="finding-section-label">Fix</div><div className="finding-section-text">{f.recommendation}</div></div>}
                  </div>
                ))
              }
            </div>
          </>
        )
      }
    </div>
  )
}
