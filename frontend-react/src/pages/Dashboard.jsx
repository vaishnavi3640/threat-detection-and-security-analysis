import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { LayoutDashboard, Shield, AlertTriangle, Globe, TrendingUp, Zap } from 'lucide-react'
import { RadialBarChart, RadialBar, ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts'
import api from '../api'
import '../components/shared.css'
import './Dashboard.css'

const SEV_COLORS = { Critical:'#ef4444', High:'#f97316', Medium:'#eab308', Low:'#3b82f6', Informational:'#64748b' }

function ScoreGauge({ value, label, color }) {
  const data = [{ value, fill: color }, { value: 100 - value, fill: 'rgba(30,58,95,.35)' }]
  return (
    <div className="score-ring-wrap">
      <div style={{ width: 100, height: 100, position: 'relative' }}>
        <ResponsiveContainer width="100%" height="100%">
          <RadialBarChart cx="50%" cy="50%" innerRadius="70%" outerRadius="100%" startAngle={90} endAngle={-270} data={data}>
            <RadialBar dataKey="value" cornerRadius={8} />
          </RadialBarChart>
        </ResponsiveContainer>
        <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center' }}>
          <span className="score-ring-num" style={{ color }}>{value}</span>
        </div>
      </div>
      <span className="score-ring-label">{label}</span>
    </div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [recentScans, setRecentScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([api.dashboard(), api.listScans()])
      .then(([d, s]) => { setData(d.data); setRecentScans(s.data.slice(0, 5)) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="spinner" />

  const sevData = data
    ? Object.entries(data.severity_distribution).filter(([,v]) => v > 0).map(([k,v]) => ({ name: k, value: v }))
    : []

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title"><LayoutDashboard size={26} /> Dashboard</h1>
        <p className="page-subtitle">Overview of all security scans and findings</p>
      </div>

      {/* KPI Cards */}
      <div className="grid-4" style={{ marginBottom: 24 }}>
        <div className="stat-card blue">
          <Shield size={40} className="stat-icon" />
          <span className="stat-label">Total Scans</span>
          <span className="stat-value">{data?.total_scans ?? 0}</span>
          <span className="stat-sub">Completed successfully</span>
        </div>
        <div className="stat-card green">
          <Globe size={40} className="stat-icon" />
          <span className="stat-label">Sites Analyzed</span>
          <span className="stat-value">{data?.total_sites ?? 0}</span>
          <span className="stat-sub">Unique domains</span>
        </div>
        <div className="stat-card orange">
          <AlertTriangle size={40} className="stat-icon" />
          <span className="stat-label">Total Findings</span>
          <span className="stat-value">{data?.total_findings ?? 0}</span>
          <span className="stat-sub">Across all scans</span>
        </div>
        <div className="stat-card red">
          <Zap size={40} className="stat-icon" />
          <span className="stat-label">Critical Issues</span>
          <span className="stat-value">{data?.severity_distribution?.Critical ?? 0}</span>
          <span className="stat-sub">Needs immediate action</span>
        </div>
      </div>

      <div className="grid-2" style={{ marginBottom: 24 }}>
        {/* Average Scores */}
        <div className="card">
          <h3 className="card-title">Average Scores</h3>
          <div className="scores-row">
            <ScoreGauge value={Math.round(data?.avg_security_score ?? 0)} label="Security" color="#3b82f6" />
            <ScoreGauge value={Math.round(data?.avg_privacy_score ?? 0)} label="Privacy" color="#a855f7" />
            <ScoreGauge value={Math.round(data?.avg_trust_score ?? 0)} label="Trust" color="#22c55e" />
          </div>
        </div>

        {/* Severity Distribution Pie */}
        <div className="card">
          <h3 className="card-title">Findings by Severity</h3>
          {sevData.length === 0 ? (
            <div className="empty-state"><p>No findings yet. Run a scan!</p></div>
          ) : (
            <div style={{ display:'flex', alignItems:'center', gap:24 }}>
              <ResponsiveContainer width={180} height={180}>
                <PieChart>
                  <Pie data={sevData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={3} dataKey="value">
                    {sevData.map((e,i) => <Cell key={i} fill={SEV_COLORS[e.name]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background:'#0d1f38', border:'1px solid #1e3a5f', color:'#e2e8f0' }} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pie-legend">
                {sevData.map(e => (
                  <div key={e.name} className="pie-legend-item">
                    <span className="pie-dot" style={{ background: SEV_COLORS[e.name] }} />
                    <span>{e.name}</span>
                    <span className="pie-count">{e.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="card">
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
          <h3 className="card-title" style={{ margin:0 }}>Recent Scans</h3>
          <Link to="/scan" className="btn btn-primary" style={{ padding:'8px 16px', fontSize:13 }}>+ New Scan</Link>
        </div>
        {recentScans.length === 0 ? (
          <div className="empty-state">
            <Shield size={40} />
            <h3>No scans yet</h3>
            <p>Go to Scan Website to analyze your first URL</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Domain</th><th>Security</th><th>Privacy</th><th>Trust</th><th>Findings</th><th>Date</th><th></th></tr></thead>
              <tbody>
                {recentScans.map(s => (
                  <tr key={s.scan_id}>
                    <td><span className="domain-cell">{s.domain}</span></td>
                    <td><span style={{ color:'#3b82f6', fontWeight:600 }}>{s.security_score}</span></td>
                    <td><span style={{ color:'#a855f7', fontWeight:600 }}>{s.privacy_score}</span></td>
                    <td><span style={{ color:'#22c55e', fontWeight:600 }}>{s.trust_score}</span></td>
                    <td>{s.total_findings}</td>
                    <td style={{ fontSize:12, color:'var(--text-muted)' }}>{new Date(s.scan_date).toLocaleDateString()}</td>
                    <td><Link to={`/scan/${s.scan_id}`} className="btn btn-outline" style={{ padding:'4px 12px', fontSize:12 }}>View</Link></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {data?.last_scan && (
        <div className="alert alert-info" style={{ marginTop:16 }}>
          <TrendingUp size={18} />
          <span>Last scan: <b>{data.last_scan.url}</b> — Trust Score: <b>{data.last_scan.trust_score}</b></span>
        </div>
      )}
    </div>
  )
}
