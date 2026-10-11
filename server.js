const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const keySchema = new mongoose.Schema({
  key: { type: String, required: true, unique: true },
  cookies: { type: Array, required: true },
  status: { type: String, default: 'inactive' },
  activeDeviceId: { type: String, default: null },
  revoked: { type: Boolean, default: false }
});
const Key = mongoose.model('Key', keySchema);

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB Connected'));

// ACTIVATE: Return cookies
app.post('/api/activate', async (req, res) => {
  const { licenseKey, deviceId } = req.body;
  const keyDoc = await Key.findOne({ key: licenseKey });
  if (!keyDoc) return res.status(404).json({ error: 'Invalid key' });
  if (keyDoc.revoked) return res.status(403).json({ error: 'Key revoked' });
  if (keyDoc.status === 'active' && keyDoc.activeDeviceId !== deviceId) {
    return res.status(403).json({ error: 'Already in use.' });
  }
  keyDoc.status = 'active';
  keyDoc.activeDeviceId = deviceId;
  await keyDoc.save();
  res.json({ cookies: keyDoc.cookies });
});

// HEARTBEAT: Check revocation
app.post('/api/heartbeat', async (req, res) => {
  const { key, deviceId } = req.body;
  const keyDoc = await Key.findOne({ key });
  if (!keyDoc || keyDoc.revoked) return res.json({ revoked: true });
  if (keyDoc.activeDeviceId !== deviceId) return res.json({ revoked: true });
  res.json({ cookies: keyDoc.cookies, revoked: false });
});

// LOGOUT
app.post('/api/logout', async (req, res) => {
  const { key, deviceId } = req.body;
  await Key.findOneAndUpdate(
    { key, activeDeviceId: deviceId },
    { status: 'inactive', activeDeviceId: null }
  );
  res.json({ success: true });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => console.log(`Server on ${PORT}`));