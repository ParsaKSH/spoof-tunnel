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

  // Inbounds
  listInbounds: () => request('/inbounds'),
  createInbound: (data: any) => request('/inbounds', { method: 'POST', body: JSON.stringify(data) }),
  updateInbound: (id: number, data: any) => request(`/inbounds/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteInbound: (id: number) => request(`/inbounds/${id}`, { method: 'DELETE' }),

  // Config
  getConfig: () => request('/config'),
  updateConfig: (data: any) => request('/config', { method: 'PUT', body: JSON.stringify(data) }),

  // Tunnel
  tunnelStart: () => request('/tunnel/start', { method: 'POST' }),
  tunnelStop: () => request('/tunnel/stop', { method: 'POST' }),
  tunnelRestart: () => request('/tunnel/restart', { method: 'POST' }),
  tunnelStatus: () => request('/tunnel/status'),

  // Settings
  changePassword: (oldPassword: string, newPassword: string) =>
    request('/settings/password', { method: 'PUT', body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }) }),
};
