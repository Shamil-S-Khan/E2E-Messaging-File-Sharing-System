import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const SecurityLogs = () => {
    const navigate = useNavigate();
    const [logs, setLogs] = useState([]);
    const [stats, setStats] = useState([]);
    const [filter, setFilter] = useState('all');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState('');

    const API_URL = 'http://localhost:5000/api/security';

    const getAuthHeaders = () => {
        const user = JSON.parse(localStorage.getItem('user'));
        return {
            headers: {
                Authorization: `Bearer ${user?.token}`,
            },
        };
    };

    useEffect(() => {
        fetchLogs();
        fetchStats();
        // Refresh every 10 seconds
        const interval = setInterval(() => {
            fetchLogs();
            fetchStats();
        }, 10000);
        return () => clearInterval(interval);
    }, [filter]);

    const fetchLogs = async () => {
        try {
            const params = filter !== 'all' ? `?eventType=${filter}` : '';
            const response = await axios.get(`${API_URL}/logs${params}`, getAuthHeaders());
            setLogs(response.data.logs);
            setLoading(false);
        } catch (err) {
            console.error('Failed to fetch logs:', err);
            setError('Failed to load security logs');
            setLoading(false);
        }
    };

    const fetchStats = async () => {
        try {
            const response = await axios.get(`${API_URL}/stats`, getAuthHeaders());
            setStats(response.data.statistics);
        } catch (err) {
            console.error('Failed to fetch stats:', err);
        }
    };

    const getSeverityColor = (severity) => {
        const colors = {
            info: '#3b82f6',
            warning: '#f59e0b',
            error: '#ef4444',
            critical: '#dc2626'
        };
        return colors[severity] || '#6b7280';
    };

    const formatTimestamp = (timestamp) => {
        return new Date(timestamp).toLocaleString();
    };

    if (loading) {
        return (
            <div className="container">
                <div className="card">
                    <p>Loading security logs...</p>
                </div>
            </div>
        );
    }

    return (
        <div className="container">
            <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <h3 style={{ margin: 0 }}>🔒 Security Logs & Monitoring</h3>
                    <button
                        className="btn-secondary"
                        onClick={() => navigate('/')}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                        ← Back to Dashboard
                    </button>
                </div>
            </div>

            {/* Statistics */}
            <div className="card" style={{ marginBottom: '1rem' }}>
                <h4>📊 Security Statistics (Last 24 Hours)</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
                    {stats.map((stat) => (
                        <div key={stat._id} style={{
                            padding: '1rem',
                            background: '#f9fafb',
                            borderRadius: '6px',
                            border: '1px solid #e5e7eb'
                        }}>
                            <div style={{ fontSize: '0.85rem', color: '#6b7280', marginBottom: '0.25rem' }}>
                                {stat._id.replace(/_/g, ' ').toUpperCase()}
                            </div>
                            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: '#111827' }}>
                                {stat.count}
                            </div>
                            {stat.criticalCount > 0 && (
                                <div style={{ fontSize: '0.75rem', color: '#ef4444', marginTop: '0.25rem' }}>
                                    {stat.criticalCount} critical
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            </div>

            {/* Filter */}
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <button
                        className={filter === 'all' ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => setFilter('all')}
                        style={{ padding: '0.5rem 1rem', fontSize: '0.9rem' }}
                    >
                        All Events
                    </button>
                    <button
                        className={filter === 'auth_failure' ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => setFilter('auth_failure')}
                        style={{ padding: '0.5rem 1rem', fontSize: '0.9rem' }}
                    >
                        Auth Failures
                    </button>
                    <button
                        className={filter === 'replay_attack_detected' ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => setFilter('replay_attack_detected')}
                        style={{ padding: '0.5rem 1rem', fontSize: '0.9rem' }}
                    >
                        Replay Attacks
                    </button>
                    <button
                        className={filter === 'invalid_signature' ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => setFilter('invalid_signature')}
                        style={{ padding: '0.5rem 1rem', fontSize: '0.9rem' }}
                    >
                        Invalid Signatures
                    </button>
                    <button
                        className={filter === 'message_decryption_failed' ? 'btn-primary' : 'btn-secondary'}
                        onClick={() => setFilter('message_decryption_failed')}
                        style={{ padding: '0.5rem 1rem', fontSize: '0.9rem' }}
                    >
                        Decryption Failures
                    </button>
                </div>
            </div>

            {/* Logs Table */}
            <div className="card">
                <h4>📋 Security Event Log</h4>
                {error && <div className="error-message">{error}</div>}

                {logs.length === 0 ? (
                    <p style={{ color: '#6b7280', textAlign: 'center', padding: '2rem' }}>
                        No security events found
                    </p>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.9rem' }}>
                            <thead>
                                <tr style={{ borderBottom: '2px solid #e5e7eb', textAlign: 'left' }}>
                                    <th style={{ padding: '0.75rem' }}>Timestamp</th>
                                    <th style={{ padding: '0.75rem' }}>Event Type</th>
                                    <th style={{ padding: '0.75rem' }}>Severity</th>
                                    <th style={{ padding: '0.75rem' }}>User</th>
                                    <th style={{ padding: '0.75rem' }}>IP Address</th>
                                    <th style={{ padding: '0.75rem' }}>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {logs.map((log, index) => (
                                    <tr key={log._id || index} style={{ borderBottom: '1px solid #e5e7eb' }}>
                                        <td style={{ padding: '0.75rem', fontSize: '0.85rem' }}>
                                            {formatTimestamp(log.timestamp)}
                                        </td>
                                        <td style={{ padding: '0.75rem' }}>
                                            {log.eventType.replace(/_/g, ' ')}
                                        </td>
                                        <td style={{ padding: '0.75rem' }}>
                                            <span style={{
                                                padding: '0.25rem 0.5rem',
                                                borderRadius: '4px',
                                                fontSize: '0.75rem',
                                                fontWeight: 'bold',
                                                color: 'white',
                                                background: getSeverityColor(log.severity)
                                            }}>
                                                {log.severity.toUpperCase()}
                                            </span>
                                        </td>
                                        <td style={{ padding: '0.75rem' }}>
                                            {log.userId?.username || 'N/A'}
                                        </td>
                                        <td style={{ padding: '0.75rem', fontSize: '0.85rem' }}>
                                            {log.ipAddress || 'N/A'}
                                        </td>
                                        <td style={{ padding: '0.75rem', fontSize: '0.85rem', maxWidth: '300px' }}>
                                            <details>
                                                <summary style={{ cursor: 'pointer', color: '#3b82f6' }}>
                                                    View Details
                                                </summary>
                                                <pre style={{
                                                    marginTop: '0.5rem',
                                                    padding: '0.5rem',
                                                    background: '#f9fafb',
                                                    borderRadius: '4px',
                                                    fontSize: '0.75rem',
                                                    overflow: 'auto'
                                                }}>
                                                    {JSON.stringify(log.details, null, 2)}
                                                </pre>
                                            </details>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};

export default SecurityLogs;
