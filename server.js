const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// --- DATABASE MODEL ---
const keySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  nftoken: { type: String, required: true },
  status: { type: String, default: 'inactive' },
  activeDeviceId: { type: String, default: null },
  lastHeartbeat: { type: Date, default: null },
  revoked: { type: Boolean, default: false }
});
const Key = mongoose.model('Key', keySchema);

// --- CONNECT TO DATABASE ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB error:', err));

// --- ACTIVATE: Bind key to device ---
app.post('/api/activate', async (req, res) => {
  try {
    const { licenseKey, deviceId } = req.body;
    const keyDoc = await Key.findOne({ key: licenseKey });
    if (!keyDoc) return res.status(404).json({ error: 'Invalid key' });
    if (keyDoc.revoked) return res.status(403).json({ error: 'Key revoked' });
    if (keyDoc.status === 'active' && keyDoc.activeDeviceId !== deviceId) {
      return res.status(403).json({ error: 'Already in use on another browser.' });
    }
    keyDoc.status = 'active';
    keyDoc.activeDeviceId = deviceId;
    keyDoc.lastHeartbeat = new Date();
    await keyDoc.save();
    
    // CHANGED: Return nftoken instead of cookies
    res.json({ nftoken: keyDoc.nftoken });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- HEARTBEAT: Check for updates ---
app.post('/api/heartbeat', async (req, res) => {
  try {
    const { key, deviceId } = req.body;
    const keyDoc = await Key.findOne({ key });
    if (!keyDoc || keyDoc.revoked) return res.json({ revoked: true });
    if (keyDoc.activeDeviceId !== deviceId) return res.json({ revoked: true, reason: 'Logged in elsewhere' });
    keyDoc.lastHeartbeat = new Date();
    await keyDoc.save();
    res.json({ cookies: keyDoc.cookies, revoked: false });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// --- LOGOUT ---
app.post('/api/logout', async (req, res) => {
  try {
    const { key, deviceId } = req.body;
    await Key.findOneAndUpdate(
      { key, activeDeviceId: deviceId },
      { status: 'inactive', activeDeviceId: null }
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});