import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Shield, Zap, Lock, Eye } from 'lucide-react'
import toast from 'react-hot-toast'
import api from '../api'
import '../components/shared.css'
import './ScanPage.css'

const EXAMPLES = ['https://github.com', 'https://wikipedia.org', 'https://mozilla.org', 'https://python.org']

export default function ScanPage() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const navigate = useNavigate()

  const handleScan = async (e) => {
    e.preventDefault()
    if (!url.trim()) { toast.error('Enter a URL to scan'); return }
    setScanning(true)
    const toastId = toast.loading('Scanning… this may take 20–60 seconds', { duration: 90000 })
    try {
      const { data } = await api.scan(url.trim())
      toast.dismiss(toastId)
      toast.success(`Scan complete! Trust score: ${data.trust_score}`)
      navigate(`/scan/${data.scan_id}`)
    } catch (err) {
      toast.dismiss(toastId)
      toast.error(err?.response?.data?.error || 'Scan failed — check URL and try again')
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="scan-page">
      <div className="page-header">
        <h1 className="page-title"><Search size={26} /> Scan Website</h1>
        <p className="page-subtitle">Enter a public URL to run a full security & privacy analysis</p>
      </div>

      <div className="scan-hero">
        <div className="scan-hero-icon">
          <Shield size={60} />
        </div>
        <h2 className="scan-hero-title">Website Security & Privacy Analysis</h2>
        <p className="scan-hero-sub">Passive, non-intrusive scanning of HTTPS, headers, cookies, TLS, trackers &amp; more</p>

        <form onSubmit={handleScan} className="scan-form">
          <div className="scan-input-wrap">
            <Search size={18} className="scan-input-icon" />
            <input
              type="url"
              className="scan-input"
              placeholder="https://example.com"
              value={url}
              onChange={e => setUrl(e.target.value)}
              disabled={scanning}
              autoFocus
            />
            <button type="submit" className="btn btn-primary scan-btn" disabled={scanning}>
              {scanning ? <span className="btn-spinner" /> : <Zap size={16} />}
              {scanning ? 'Scanning…' : 'Scan Now'}
            </button>
          </div>
        </form>

        <div className="examples-row">
          <span className="examples-label">Try:</span>
          {EXAMPLES.map(ex => (
            <button key={ex} className="example-pill" onClick={() => setUrl(ex)} disabled={scanning}>
              {ex.replace('https://', '')}
            </button>
          ))}
        </div>
      </div>

      {/* Features */}
      <div className="grid-3" style={{ marginTop: 32 }}>
        <div className="card card-sm scan-feature">
          <Lock size={22} style={{ color:'#3b82f6', marginBottom:10 }} />
          <h4>Security Analysis</h4>
          <p>HTTPS, TLS cert, security headers, cookie flags, redirect checks</p>
        </div>
        <div className="card card-sm scan-feature">
          <Eye size={22} style={{ color:'#a855f7', marginBottom:10 }} />
          <h4>Privacy Analysis</h4>
          <p>Tracker detection, 3rd-party scripts, ad networks, privacy policy check</p>
        </div>
        <div className="card card-sm scan-feature">
          <Shield size={22} style={{ color:'#22c55e', marginBottom:10 }} />
          <h4>Trust Score</h4>
          <p>Combined 0–100 trust score with actionable recommendations</p>
        </div>
      </div>

      <div className="alert alert-warn" style={{ marginTop: 20 }}>
        ⚠️ Only scan websites you own or are authorized to test. All scans are passive and non-intrusive.
      </div>
    </div>
  )
}
