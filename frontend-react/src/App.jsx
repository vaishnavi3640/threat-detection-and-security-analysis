import { BrowserRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { Shield, LayoutDashboard, Search, Lock, Eye, AlertTriangle, FileText, History, RefreshCw, Menu, X } from 'lucide-react'
import { useState } from 'react'
import Dashboard from './pages/Dashboard'
import ScanPage from './pages/ScanPage'
import ScanResult from './pages/ScanResult'
import SecurityPage from './pages/SecurityPage'
import PrivacyPage from './pages/PrivacyPage'
import WeaknessesPage from './pages/WeaknessesPage'
import ReportsPage from './pages/ReportsPage'
import HistoryPage from './pages/HistoryPage'
import ReassessPage from './pages/ReassessPage'
import './App.css'

const NAV = [
  { to: '/',             icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scan',         icon: Search,          label: 'Scan Website' },
  { to: '/security',     icon: Lock,            label: 'Security' },
  { to: '/privacy',      icon: Eye,             label: 'Privacy' },
  { to: '/weaknesses',   icon: AlertTriangle,   label: 'Weaknesses' },
  { to: '/reports',      icon: FileText,        label: 'Reports' },
  { to: '/reassess',     icon: RefreshCw,       label: 'Reassessment' },
  { to: '/history',      icon: History,         label: 'History' },
]

function Sidebar({ open, onClose }) {
  return (
    <>
      {open && <div className="sidebar-overlay" onClick={onClose} />}
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="sidebar-brand">
          <Shield size={28} className="brand-icon" />
          <span className="brand-text">Threat<b>Guard</b></span>
        </div>
        <nav className="sidebar-nav">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              onClick={onClose}
            >
              <Icon size={18} />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div className="trust-pill">
            <span className="dot green" />
            <span>System Online</span>
          </div>
          <p className="sidebar-version">v1.0.0 · ThreatGuard</p>
        </div>
      </aside>
    </>
  )
}

function TopBar({ onMenu }) {
  return (
    <header className="topbar">
      <button className="menu-btn" onClick={onMenu} aria-label="Menu">
        <Menu size={22} />
      </button>
      <div className="topbar-brand">
        <Shield size={20} className="brand-icon" />
        <span>ThreatGuard</span>
      </div>
      <div className="topbar-status">
        <span className="status-dot green" />
        <span className="status-text">Live</span>
      </div>
    </header>
  )
}

function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  return (
    <div className="app-layout">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="main-wrap">
        <TopBar onMenu={() => setSidebarOpen(o => !o)} />
        <main className="main-content">
          <Routes>
            <Route path="/"           element={<Dashboard />} />
            <Route path="/scan"       element={<ScanPage />} />
            <Route path="/scan/:id"   element={<ScanResult />} />
            <Route path="/security"   element={<SecurityPage />} />
            <Route path="/privacy"    element={<PrivacyPage />} />
            <Route path="/weaknesses" element={<WeaknessesPage />} />
            <Route path="/reports"    element={<ReportsPage />} />
            <Route path="/reassess"   element={<ReassessPage />} />
            <Route path="/history"    element={<HistoryPage />} />
          </Routes>
        </main>
      </div>
      <Toaster position="bottom-right" toastOptions={{ style: { background: '#0d1f38', color: '#e2e8f0', border: '1px solid #1e3a5f' } }} />
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Layout />
    </BrowserRouter>
  )
}
