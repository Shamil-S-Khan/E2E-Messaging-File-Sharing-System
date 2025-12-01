import axios from 'axios';

const API_URL = 'http://localhost:5000/api/auth';

const register = async (username, password) => {
  const response = await axios.post(`${API_URL}/register`, { username, password });
  if (response.data.token) {
    localStorage.setItem('user', JSON.stringify(response.data));
  }
  return response.data;
};

const login = async (username, password) => {
  const response = await axios.post(`${API_URL}/login`, { username, password });
  if (response.data.token) {
    localStorage.setItem('user', JSON.stringify(response.data));
  }
  return response.data;
};

const logout = () => {
  localStorage.removeItem('user');
};

const uploadPublicKey = async (publicKey) => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user || !user.token) {
    throw new Error('User not authenticated.');
  }

  const config = {
    headers: {
      Authorization: `Bearer ${user.token}`,
      'Content-Type': 'application/json',
    },
  };

  const response = await axios.put(`${API_URL}/publicKey`, { publicKey }, config);
  return response.data;
};

const getProfile = async () => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user || !user.token) {
    throw new Error('User not authenticated.');
  }

  const config = {
    headers: {
      Authorization: `Bearer ${user.token}`,
    },
  };

  const response = await axios.get(`${API_URL}/profile`, config);
  return response.data;
};

const getUsers = async () => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user || !user.token) {
    throw new Error('User not authenticated.');
  }

  const config = {
    headers: {
      Authorization: `Bearer ${user.token}`,
    },
  };

  const response = await axios.get(`${API_URL}/users`, config);
  return response.data;
};

const authService = {
  register,
  login,
  logout,
  uploadPublicKey,
  getProfile,
  getUsers,
};

export default authService;