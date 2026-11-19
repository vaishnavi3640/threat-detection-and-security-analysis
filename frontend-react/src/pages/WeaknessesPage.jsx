import { useEffect, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import api from '../api'
import '../components/shared.css'

const SEV_ORDER = { Critical:0, High:1, Medium:2, Low:3, Informational:4 }

export default function WeaknessesPage() {
  const [scans, setScans] = useState([])
  const [selected, setSelected] = useState(null)
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [filterSev, setFilterSev] = useState('All')

  useEffect(() => {
    api.listScans().then(r => {
      setScans(r.data)
      if (r.data.length) setSelected(r.data[0].scan_id)
    }).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    if (selected) api.getFindings(selected).then(r => setFindings(r.data))
  }, [selected])

  if (loading) return <div className="spinner" />

  const filtered = filterSev === 'All' ? findings : findings.filter(f => f.severity === filterSev)
  const sorted = [...filtered].sort((a,b) => (SEV_ORDER[a.severity]??9)-(SEV_ORDER[b.severity]??9))

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><AlertTriangle size={26} /> Weaknesses</h1>
        <p className="page-subtitle">All vulnerabilities sorted by severity</p>
      </div>
      {scans.length === 0
        ? <div className="empty-state"><AlertTriangle size={40}/><h3>No scans available</h3></div>
        : (
          <>
            <div style={{ display:'flex', gap:12, marginBottom:20, flexWrap:'wrap' }}>
              <select style={{ background:'var(--bg-hover)', border:'1px solid var(--border)', color:'var(--text-prim)', padding:'8px 12px', borderRadius:8, fontSize:13 }}
                value={selected} onChange={e => setSelected(Number(e.target.value))}>
                {scans.map(s => <option key={s.scan_id} value={s.scan_id}>{s.domain} — {new Date(s.scan_date).toLocaleDateString()}</option>)}
              </select>
              <select style={{ background:'var(--bg-hover)', border:'1px solid var(--border)', color:'var(--text-prim)', padding:'8px 12px', borderRadius:8, fontSize:13 }}
                value={filterSev} onChange={e => setFilterSev(e.target.value)}>
                {['All','Critical','High','Medium','Low','Informational'].map(s=><option key={s}>{s}</option>)}
              </select>
            </div>
            <div className="card">
              <h3 className="card-title">Weaknesses ({sorted.length})</h3>
              {sorted.length === 0
                ? <div className="empty-state"><h3>No weaknesses matching filter</h3></div>
                : sorted.map(f => (
                  <div key={f.id} className="finding-card">
                    <div className="finding-header">
                      <div>
                        <div className="finding-name">{f.finding_name}</div>
                        <div className="finding-meta">{f.category} · {f.confidence} confidence</div>
                      </div>
                      <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                    </div>
                    {f.evidence && <div className="finding-section"><div className="finding-section-label">Evidence</div><div className="finding-evidence">{f.evidence}</div></div>}
                    {f.impact && <div className="finding-section"><div className="finding-section-label">Impact</div><div className="finding-section-text">{f.impact}</div></div>}
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
