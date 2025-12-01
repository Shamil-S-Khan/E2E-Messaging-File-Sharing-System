import React, { useState, useEffect, useRef } from 'react';
import { useAuth } from '../context/AuthContext';
import authService from '../services/authService';
import fileService from '../services/fileService';
import securityService from '../services/securityService';

const FileSharing = () => {
  const { user, sessionKeys, getSessionKey } = useAuth();
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedPeer, setSelectedPeer] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [downloadProgress, setDownloadProgress] = useState({});
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [availableUsers, setAvailableUsers] = useState([]);
  const fileInputRef = useRef(null);

  // Get peers with established session keys
  const availablePeers = Object.keys(sessionKeys);

  // Fetch users to get usernames
  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const users = await authService.getUsers();
        setAvailableUsers(users);
      } catch (err) {
        console.error('Failed to fetch users:', err);
      }
    };
    if (user) {
      fetchUsers();
    }
  }, [user]);

  // Fetch file list
  const fetchFiles = async () => {
    try {
      const fileList = await fileService.listFiles();
      setFiles(fileList);
    } catch (err) {
      console.error('Failed to fetch files:', err);
    }
  };

  useEffect(() => {
    if (user) {
      fetchFiles();
      // Poll for new files every 10 seconds
      const interval = setInterval(fetchFiles, 10000);
      return () => clearInterval(interval);
    }
  }, [user]);

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedFile(file);
      setError('');
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setError('Please select a file first');
      return;
    }
    if (!selectedPeer) {
      setError('Please select a recipient');
      return;
    }

    const sessionKey = getSessionKey(selectedPeer);
    if (!sessionKey) {
      setError('No session key found for this peer. Complete key exchange first.');
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);
    setError('');
    setSuccess('');

    try {
      await fileService.uploadEncryptedFile(
        selectedFile,
        selectedPeer,
        sessionKey,
        (progress) => setUploadProgress(progress)
      );
      setSuccess(`File "${selectedFile.name}" uploaded successfully!`);
      setSelectedFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      fetchFiles(); // Refresh file list
    } catch (err) {
      console.error('Upload failed:', err);
      setError(`Upload failed: ${err.response?.data?.message || err.message}`);
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
    }
  };

  const handleDownload = async (file) => {
    // Determine who the peer is (sender if we're receiver, receiver if we're sender)
    const peerId = file.senderId._id === user._id ? file.receiverId._id : file.senderId._id;
    const sessionKey = getSessionKey(peerId);

    if (!sessionKey) {
      setError('No session key found. Cannot decrypt this file.');
      return;
    }

    setDownloadProgress(prev => ({ ...prev, [file.fileId]: 0 }));
    setError('');

    try {
      const { blob, fileName } = await fileService.downloadEncryptedFile(
        file.fileId,
        sessionKey,
        (progress) => setDownloadProgress(prev => ({ ...prev, [file.fileId]: progress }))
      );

      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setSuccess(`File "${fileName}" downloaded successfully!`);
    } catch (err) {
      console.error('Download failed:', err);
      // Report security event if decryption failed
      if (err.message && err.message.includes('decrypt')) {
        securityService.reportSecurityEvent('decryption_failure', {
          fileId: file.fileId,
          fileName: file.fileName,
          peerId: peerId,
          error: err.message
        });
      }
      setError(`Download failed: ${err.response?.data?.message || err.message}`);
    } finally {
      setDownloadProgress(prev => {
        const newProgress = { ...prev };
        delete newProgress[file.fileId];
        return newProgress;
      });
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  };

  const formatDate = (dateStr) => {
    return new Date(dateStr).toLocaleString();
  };

  if (!user) {
    return <div className="card">Please log in to use file sharing.</div>;
  }

  return (
    <div className="card" style={{ marginTop: '2rem' }}>
      <h3>📁 File Sharing</h3>
      <p style={{ color: '#6b7280', marginBottom: '1rem', fontSize: '0.9rem' }}>
        Share encrypted files securely with your contacts.
      </p>

      {error && <div className="error-message" style={{ marginBottom: '1rem' }}>{error}</div>}
      {success && <div className="success-message" style={{ marginBottom: '1rem', background: '#d4edda', color: '#155724', padding: '0.75rem', borderRadius: '6px' }}>{success}</div>}

      {/* Upload Section */}
      <div style={{ marginBottom: '1.5rem', padding: '1rem', background: '#f9fafb', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
        <h4 style={{ marginBottom: '0.75rem', fontSize: '1rem' }}>📤 Send File</h4>

        {availablePeers.length === 0 ? (
          <p style={{ color: '#ef4444', fontSize: '0.85rem', margin: 0 }}>
            No contacts available. Complete a key exchange first.
          </p>
        ) : (
          <>
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
              <select
                className="form-input"
                value={selectedPeer}
                onChange={(e) => setSelectedPeer(e.target.value)}
                disabled={isUploading}
                style={{ flex: 1, minWidth: '150px' }}
              >
                <option value="">-- Select Recipient --</option>
                {availablePeers.map(peerId => {
                  const peerUser = availableUsers.find(u => u._id === peerId);
                  const displayName = peerUser ? peerUser.username : `${peerId.substring(0, 8)}...`;
                  return (
                    <option key={peerId} value={peerId}>
                      {displayName}
                    </option>
                  );
                })}
              </select>

              <input
                ref={fileInputRef}
                type="file"
                onChange={handleFileSelect}
                disabled={isUploading}
                style={{ flex: 1, minWidth: '150px' }}
              />
            </div>

            {selectedFile && (
              <p style={{ fontSize: '0.85rem', color: '#6b7280', marginBottom: '0.75rem' }}>
                {selectedFile.name} ({formatFileSize(selectedFile.size)})
              </p>
            )}

            {isUploading && (
              <div style={{ marginBottom: '0.75rem' }}>
                <div style={{ background: '#e5e7eb', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
                  <div style={{
                    background: '#3b82f6',
                    height: '100%',
                    width: `${uploadProgress}%`,
                    transition: 'width 0.3s ease'
                  }} />
                </div>
                <p style={{ fontSize: '0.75rem', color: '#6b7280', marginTop: '0.25rem' }}>
                  Encrypting... {uploadProgress}%
                </p>
              </div>
            )}

            <button
              className="btn-primary"
              onClick={handleUpload}
              disabled={!selectedFile || !selectedPeer || isUploading}
              style={{ width: 'auto' }}
            >
              {isUploading ? 'Uploading...' : '🔐 Send'}
            </button>
          </>
        )}
      </div>

      {/* Files List Section */}
      <div>
        <h4 style={{ marginBottom: '0.75rem', fontSize: '1rem' }}>📂 Files</h4>

        {files.length === 0 ? (
          <p style={{ color: '#6b7280', padding: '1rem', background: '#f9fafb', borderRadius: '6px', textAlign: 'center', fontSize: '0.85rem', margin: 0 }}>
            No files yet
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {files.map(file => {
              const isSender = file.senderId._id === user._id;
              const peerName = isSender ? file.receiverId.username : file.senderId.username;
              const isDownloading = downloadProgress[file.fileId] !== undefined;

              return (
                <div
                  key={file.fileId}
                  style={{
                    padding: '0.75rem',
                    background: '#fff',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '0.75rem'
                  }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: '600', fontSize: '0.9rem', marginBottom: '0.25rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {file.fileName}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: '#6b7280' }}>
                      {formatFileSize(file.fileSize)} • {isSender ? `To ${peerName}` : `From ${peerName}`}
                    </div>
                  </div>

                  <div>
                    {isDownloading ? (
                      <div style={{ width: '80px' }}>
                        <div style={{ background: '#e5e7eb', borderRadius: '4px', height: '4px', overflow: 'hidden' }}>
                          <div style={{
                            background: '#10b981',
                            height: '100%',
                            width: `${downloadProgress[file.fileId]}%`,
                            transition: 'width 0.3s ease'
                          }} />
                        </div>
                        <p style={{ fontSize: '0.7rem', color: '#6b7280', marginTop: '0.25rem', textAlign: 'center' }}>
                          {downloadProgress[file.fileId]}%
                        </p>
                      </div>
                    ) : (
                      <button
                        className="btn-secondary"
                        onClick={() => handleDownload(file)}
                        style={{ padding: '0.4rem 0.75rem', fontSize: '0.85rem', whiteSpace: 'nowrap' }}
                      >
                        ⬇️ Download
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default FileSharing;
