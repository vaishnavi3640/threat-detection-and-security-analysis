import axios from 'axios'

const api = axios.create({
  baseURL: '/api',
  timeout: 120000,
  headers: { 'Content-Type': 'application/json' },
})

export default {
  health:          ()           => api.get('/health'),
  dashboard:       ()           => api.get('/dashboard'),
  scan:            (url)        => api.post('/scan', { url }),
  getScan:         (id)         => api.get(`/scans/${id}`),
  listScans:       ()           => api.get('/scans'),
  getFindings:     (id, cat)    => api.get(`/scans/${id}/findings`, { params: cat ? { category: cat } : {} }),
  aiExplain:       (id)         => api.post(`/scans/${id}/explain`),
  generateReport:  (id)         => api.post(`/scans/${id}/report`),
  getHistory:      ()           => api.get('/history'),
  getReassessScans:(url)        => api.post('/reassess', { url }),
  compareScans:    (id1, id2)   => api.post('/reassess', { scan_id_1: id1, scan_id_2: id2 }),
}
