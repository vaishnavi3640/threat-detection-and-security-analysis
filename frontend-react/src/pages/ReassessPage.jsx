import { useState } from 'react'
import { RefreshCw, ArrowRight } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../api'
import '../components/shared.css'

export default function ReassessPage() {
  const [url, setUrl] = useState('')
  const [scans, setScans] = useState([])
  const [scan1, setScan1] = useState('')
  const [scan2, setScan2] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const fetchScans = async () => {
    if (!url.trim()) { toast.error('Enter a URL'); return }
    setLoading(true)
    try {
      const r = await api.getReassessScans(url.trim())
      const s = r.data.scans || []
      if (s.length < 2) { toast('Need at least 2 scans of this URL to compare', { icon: 'ℹ️' }); setScans([]); return }
      setScans(s)
      setScan1(String(s[s.length-2]?.scan_id || ''))
      setScan2(String(s[s.length-1]?.scan_id || ''))
    } catch { toast.error('Failed to fetch scans') }
    finally { setLoading(false) }
  }

  const compare = async () => {
    if (!scan1 || !scan2) { toast.error('Select both scans'); return }
    setLoading(true)
    try {
      const r = await api.compareScans(Number(scan1), Number(scan2))
      setResult(r.data)
    } catch { toast.error('Comparison failed') }
    finally { setLoading(false) }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><RefreshCw size={26} /> Reassessment</h1>
        <p className="page-subtitle">Compare two scans to track security improvements over time</p>
      </div>

      <div className="card" style={{ marginBottom:20 }}>
        <h3 className="card-title">Step 1 — Load Scans for a URL</h3>
        <div style={{ display:'flex', gap:10 }}>
          <input className="input-field" style={{ flex:1 }} placeholder="https://example.com" value={url} onChange={e=>setUrl(e.target.value)} />
          <button className="btn btn-primary" onClick={fetchScans} disabled={loading}>Fetch Scans</button>
        </div>
      </div>

      {scans.length >= 2 && (
        <div className="card" style={{ marginBottom:20 }}>
          <h3 className="card-title">Step 2 — Select Scans to Compare</h3>
          <div style={{ display:'flex', gap:16, alignItems:'center', flexWrap:'wrap' }}>
            <select style={{ background:'var(--bg-hover)', border:'1px solid var(--border)', color:'var(--text-prim)', padding:'10px 14px', borderRadius:8, fontSize:13, flex:1 }}
              value={scan1} onChange={e=>setScan1(e.target.value)}>
              {scans.map(s=><option key={s.scan_id} value={s.scan_id}>Scan #{s.scan_id} — {s.scan_date ? new Date(s.scan_date).toLocaleDateString() : ''}</option>)}
            </select>
            <ArrowRight size={20} style={{ color:'var(--text-muted)' }} />
            <select style={{ background:'var(--bg-hover)', border:'1px solid var(--border)', color:'var(--text-prim)', padding:'10px 14px', borderRadius:8, fontSize:13, flex:1 }}
              value={scan2} onChange={e=>setScan2(e.target.value)}>
              {scans.map(s=><option key={s.scan_id} value={s.scan_id}>Scan #{s.scan_id} — {s.scan_date ? new Date(s.scan_date).toLocaleDateString() : ''}</option>)}
            </select>
            <button className="btn btn-primary" onClick={compare} disabled={loading}>Compare</button>
          </div>
        </div>
      )}

      {result && (
        <div>
          <div className="grid-3" style={{ marginBottom:20 }}>
            {[
              { label:'Security Δ', val: (result.new?.security_score - result.old?.security_score)?.toFixed(1), color:'#3b82f6' },
              { label:'Privacy Δ',  val: (result.new?.privacy_score  - result.old?.privacy_score)?.toFixed(1),  color:'#a855f7' },
              { label:'Trust Δ',   val: (result.new?.trust_score    - result.old?.trust_score)?.toFixed(1),    color:'#22c55e' },
            ].map(d => (
              <div key={d.label} className="card card-sm" style={{ textAlign:'center' }}>
                <div className="card-title">{d.label}</div>
                <div style={{ fontSize:32, fontWeight:800, color: Number(d.val)>=0 ? '#22c55e':'#ef4444' }}>
                  {Number(d.val)>=0?'+':''}{d.val}
                </div>
              </div>
            ))}
          </div>
          <div className="grid-3">
            {[
              { label:'✅ Resolved', items: result.resolved || [], color:'var(--green)' },
              { label:'🆕 New Findings', items: result.new_findings || [], color:'var(--red)' },
              { label:'⚠️ Remaining', items: result.remaining || [], color:'var(--orange)' },
            ].map(col => (
              <div key={col.label} className="card">
                <h3 className="card-title">{col.label} ({col.items.length})</h3>
                {col.items.length === 0
                  ? <p style={{ color:'var(--text-muted)', fontSize:13 }}>None</p>
                  : col.items.map((f,i) => (
                    <div key={i} style={{ display:'flex', justifyContent:'space-between', padding:'8px 0', borderBottom:'1px solid var(--border-dim)', fontSize:13 }}>
                      <span style={{ color:'var(--text-sec)' }}>{f.finding_name}</span>
                      {f.severity && <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>}
                    </div>
                  ))
                }
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
