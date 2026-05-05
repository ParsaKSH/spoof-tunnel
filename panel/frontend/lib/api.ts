const API_BASE = typeof window !== 'undefined' ? `${window.location.origin}/api` : '/api';

function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('token');
}

export function setToken(token: string) {
  localStorage.setItem('token', token);
}

export function clearToken() {
  localStorage.removeItem('token');
}

async function request(path: string, options: RequestInit = {}): Promise<any> {
  const token = getToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((options.headers as Record<string, string>) || {}),
  };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  
  if (res.status === 401) {
    clearToken();
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

// Auth
export const api = {
  checkAuth: () => request('/auth/check'),
  login: (username: string, password: string) =>
    request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  setup: (username: string, password: string) =>
    request('/auth/setup', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => request('/auth/me'),

  // Dashboard
  dashboard: () => request('/dashboard'),
  system: () => request('/system'),

  // Tunnel Instances
  listInstances: () => request('/instances'),
  createInstance: (data: any) => request('/instances', { method: 'POST', body: JSON.stringify(data) }),
  getInstance: (id: number) => request(`/instances/${id}`),
  updateInstance: (id: number, data: any) => request(`/instances/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteInstance: (id: number) => request(`/instances/${id}`, { method: 'DELETE' }),

  // Instance Control
  instanceStart: (id: number) => request(`/instances/${id}/start`, { method: 'POST' }),
  instanceStop: (id: number) => request(`/instances/${id}/stop`, { method: 'POST' }),
  instanceRestart: (id: number) => request(`/instances/${id}/restart`, { method: 'POST' }),
  instanceStatus: (id: number) => request(`/instances/${id}/status`),

  // Instance Spoof IPs
  getInstanceSpoofIPs: (id: number) => request(`/instances/${id}/spoof-ips`),
  setInstanceSpoofIPs: (id: number, content: string) =>
    request(`/instances/${id}/spoof-ips`, { method: 'PUT', body: JSON.stringify({ content }) }),

  // Tester
  testerStart: (data: any) => request('/tester/start', { method: 'POST', body: JSON.stringify(data) }),
  testerStatus: () => request('/tester/status'),
  testerStop: () => request('/tester/stop', { method: 'POST' }),
  testerResults: () => request('/tester/results'),
  testerDownloadUrl: () => `${API_BASE}/tester/download?token=${getToken()}`,
  testerUpload: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const token = getToken();
    const res = await fetch(`${API_BASE}/tester/upload`, {
      method: 'POST',
      headers: token ? { 'Authorization': `Bearer ${token}` } : {},
      body: formData,
    });
    if (!res.ok) throw new Error('Upload failed');
    return res.json();
  },

  // Settings
  changePassword: (oldPassword: string, newPassword: string) =>
    request('/settings/password', { method: 'PUT', body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }) }),
};
