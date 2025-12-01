import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ChatInterface from './ChatInterface';
import FileSharing from './FileSharing';

const Chats = () => {
    const navigate = useNavigate();
    const [activeTab, setActiveTab] = useState('messages'); // 'messages' or 'files'

    return (
        <div className="container">
            <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                    <h3 style={{ margin: 0 }}>💬 Secure Communications</h3>
                    <button
                        className="btn-secondary"
                        onClick={() => navigate('/')}
                        style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
                    >
                        ← Back to Dashboard
                    </button>
                </div>
                
                {/* Tab Navigation */}
                <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '2px solid var(--border-color)', paddingBottom: '0.5rem' }}>
                    <button
                        onClick={() => setActiveTab('messages')}
                        style={{
                            padding: '0.5rem 1rem',
                            border: 'none',
                            background: activeTab === 'messages' ? '#3b82f6' : 'transparent',
                            color: activeTab === 'messages' ? '#fff' : '#6b7280',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontWeight: activeTab === 'messages' ? '600' : '400',
                            transition: 'all 0.2s ease'
                        }}
                    >
                        💬 Messages
                    </button>
                    <button
                        onClick={() => setActiveTab('files')}
                        style={{
                            padding: '0.5rem 1rem',
                            border: 'none',
                            background: activeTab === 'files' ? '#3b82f6' : 'transparent',
                            color: activeTab === 'files' ? '#fff' : '#6b7280',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontWeight: activeTab === 'files' ? '600' : '400',
                            transition: 'all 0.2s ease'
                        }}
                    >
                        📁 Files
                    </button>
                </div>
            </div>
            
            {activeTab === 'messages' ? <ChatInterface /> : <FileSharing />}
        </div>
    );
};

export default Chats;
