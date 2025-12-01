import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import KeyExchangeManager from './KeyExchangeManager';
import FileSharing from './FileSharing';

const Dashboard = () => {
    const { user, sessionKeys } = useAuth();
    const navigate = useNavigate();

    const activeChatCount = Object.keys(sessionKeys || {}).length;

    return (
        <div className="container">
            <div className="card">
                <h2 style={{ marginBottom: '0.5rem' }}>🔐 Secure Messaging Dashboard</h2>
                <p style={{ color: '#6b7280', fontSize: '0.95rem' }}>
                    Welcome back, <strong>{user.username}</strong>
                </p>

                {/* Quick Actions */}
                <div style={{
                    marginTop: '2rem',
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                    gap: '1rem'
                }}>
                    <button
                        className="btn-primary"
                        onClick={() => navigate('/chats')}
                        style={{
                            padding: '1.25rem',
                            fontSize: '1rem',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '0.75rem',
                            position: 'relative',
                            borderRadius: '8px'
                        }}
                    >
                        <span style={{ fontSize: '1.5rem' }}>💬</span>
                        <span>Messages</span>
                        {activeChatCount > 0 && (
                            <span style={{
                                position: 'absolute',
                                top: '8px',
                                right: '8px',
                                background: '#ef4444',
                                color: 'white',
                                borderRadius: '12px',
                                padding: '2px 8px',
                                fontSize: '0.75rem',
                                fontWeight: 'bold'
                            }}>
                                {activeChatCount}
                            </span>
                        )}
                    </button>

                    <button
                        className="btn-secondary"
                        onClick={() => navigate('/security')}
                        style={{
                            padding: '1.25rem',
                            fontSize: '1rem',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            gap: '0.75rem',
                            borderRadius: '8px'
                        }}
                    >
                        <span style={{ fontSize: '1.5rem' }}>🔒</span>
                        <span>Security Logs</span>
                    </button>
                </div>

                {/* Key Exchange Section */}
                <KeyExchangeManager />

                {/* File Sharing Section */}
                <FileSharing />
            </div>
        </div>
    );
};

export default Dashboard;
