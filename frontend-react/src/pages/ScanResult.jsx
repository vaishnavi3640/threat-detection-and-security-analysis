import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { Shield, Lock, Eye, AlertTriangle, FileText, Sparkles, ArrowLeft, Clock } from 'lucide-react'
import { RadialBarChart, RadialBar, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts'
import toast from 'react-hot-toast'
import api from '../api'
import '../components/shared.css'
import './ScanResult.css'

const SEV_COLORS = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#3b82f6', Informational:'#64748b' }
const SEV_ORDER = { Critical:0, High:1, Medium:2, Low:3, Informational:4 }

function ScoreRing({ value, label, color }) {
  const data = [{ value, fill: color }, { value: 100 - value, fill: 'rgba(30,58,95,.3)' }]
  return (
    <div className="score-ring-wrap">
      <div style={{ width: 110, height: 110, position: 'relative' }}>
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart cx="50%" cy="50%" innerRadius="68%" outerRadius="100%" startAngle={90} endAngle={-270} data={data}>
            <RadialBar dataKey="value" cornerRadius={8} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
          <span style={{ fontSize:26, fontWeight:800, color }}>{Math.round(value)}</span>
          <span style={{ fontSize:11, color:'var(--text-muted)' }}>/100</span>
        </div>
      </div>
      <span className="score-ring-label">{label}</span>
    </div>
  )
}

function FindingCard({ f }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className="finding-card">
      <div className="finding-header">
        <div>
          <div className="finding-name">{f.finding_name}</div>
          <div className="finding-meta">{f.category} · Confidence: {f.confidence}</div>
        </div>
        <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
      </div>
      {f.evidence && (
        <div className="finding-section">
          <div className="finding-section-label">Evidence</div>
          <div className="finding-evidence">{f.evidence}</div>
        </div>
      )}
      <button className="expand-btn" onClick={() => setExpanded(e => !e)}>
        {expanded ? '▲ Less' : '▼ More details'}
      </button>
      {expanded && (
        <>
          {f.impact && (
            <div className="finding-section">
              <div className="finding-section-label">Impact</div>
              <div className="finding-section-text">{f.impact}</div>
            </div>
          )}
          {f.recommendation && (
            <div className="finding-section">
              <div className="finding-section-label">Recommendation</div>
              <div className="finding-section-text">{f.recommendation}</div>
            </div>
          )}
          {f.ai_explanation && (
            <div className="finding-section ai-explain">
              <div className="finding-section-label"><Sparkles size={12} style={{ display:'inline' }} /> AI Explanation</div>
              <div className="finding-section-text">{f.ai_explanation}</div>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default function ScanResult() {
  const { id } = useParams()
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [aiLoading, setAiLoading] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('all')

  useEffect(() => {
    api.getScan(id)
      .then(r => setScan(r.data))
      .catch(() => toast.error('Failed to load scan'))
      .finally(() => setLoading(false))
  }, [id])

  const handleAI = async () => {
    setAiLoading(true)
    try {
      await api.aiExplain(id)
      const r = await api.getScan(id)
      setScan(r.data)
      toast.success('AI explanations added!')
    } catch (e) {
      toast.error(e?.response?.data?.error || 'AI unavailable')
    } finally { setAiLoading(false) }
  }

  const handleReport = async () => {
    setReportLoading(true)
    try {
      const r = await api.generateReport(id)
      toast.success('PDF report generated: ' + r.data.report_path)
    } catch (e) {
      toast.error('Report generation failed')
    } finally { setReportLoading(false) }
  }

  if (loading) return <div className="spinner" />
  if (!scan) return <div className="empty-state"><h3>Scan not found</h3></div>

  const findings = scan.findings || []
  const filtered = activeTab === 'all' ? findings
    : activeTab === 'security' ? findings.filter(f => f.category === 'security')
    : findings.filter(f => f.category === 'privacy')

  const sorted = [...filtered].sort((a,b) => (SEV_ORDER[a.severity]??99) - (SEV_ORDER[b.severity]??99))

  const sevDist = { Critical:0, High:0, Medium:0, Low:0, Informational:0 }
  findings.forEach(f => { sevDist[f.severity] = (sevDist[f.severity]||0)+1 })
  const barData = Object.entries(sevDist).filter(([,v])=>v>0).map(([k,v])=>({name:k,value:v}))

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:24 }}>
        <Link to="/scan" className="btn btn-outline" style={{ padding:'8px 14px' }}><ArrowLeft size={16} /></Link>
        <div>
          <h1 className="page-title"><Shield size={22} /> {scan.domain}</h1>
          <p className="page-subtitle" style={{ display:'flex', gap:8, alignItems:'center' }}>
            <Clock size={12} /> {scan.scan_date ? new Date(scan.scan_date).toLocaleString() : '—'} &nbsp;·&nbsp; {scan.total_findings} findings &nbsp;·&nbsp; {scan.scan_duration}s
          </p>
        </div>
        <div style={{ marginLeft:'auto', display:'flex', gap:10 }}>
          <button className="btn btn-outline" onClick={handleAI} disabled={aiLoading}>
            <Sparkles size={15} /> {aiLoading ? 'Loading AI…' : 'AI Explain'}
          </button>
          <button className="btn btn-primary" onClick={handleReport} disabled={reportLoading}>
            <FileText size={15} /> {reportLoading ? 'Generating…' : 'PDF Report'}
          </button>
        </div>
      </div>

      {/* Score Cards */}
      <div className="result-scores-wrap">
        <div className="card result-scores-card">
          <h3 className="card-title">Scores</h3>
          <div className="result-scores-row">
            <ScoreRing value={scan.security_score} label="Security" color="#3b82f6" />
            <ScoreRing value={scan.privacy_score} label="Privacy" color="#a855f7" />
            <ScoreRing value={scan.trust_score} label="Trust" color="#22c55e" />
          </div>
        </div>
        <div className="card result-dist-card">
          <h3 className="card-title">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={barData} margin={{ top:5, right:10, bottom:5, left:-20 }}>
              <XAxis dataKey="name" tick={{ fill:'#94a3b8', fontSize:11 }} />
              <YAxis tick={{ fill:'#94a3b8', fontSize:11 }} />
              <Tooltip contentStyle={{ background:'#0d1f38', border:'1px solid #1e3a5f', color:'#e2e8f0' }} />
              <Bar dataKey="value" radius={[4,4,0,0]}>
                {barData.map((e,i) => <Cell key={i} fill={SEV_COLORS[e.name]} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Findings */}
      <div className="card" style={{ marginTop: 20 }}>
        <div style={{ display:'flex', gap:8, marginBottom:20, flexWrap:'wrap' }}>
          {['all','security','privacy'].map(t => (
            <button key={t} className={`tab-btn ${activeTab===t?'active':''}`} onClick={() => setActiveTab(t)}>
              {t==='all'?'All Findings':t==='security'?<><Lock size={14}/> Security</>:<><Eye size={14}/> Privacy</>}
              <span className="tab-count">{t==='all'?findings.length:findings.filter(f=>f.category===t).length}</span>
            </button>
          ))}
        </div>
        {sorted.length === 0
          ? <div className="empty-state"><Shield size={36} /><h3>No findings in this category</h3></div>
          : sorted.map(f => <FindingCard key={f.id} f={f} />)
        }
      </div>
    </div>
  )
}
