// server.js

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors'); // Make sure cors is required
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5001;

// --- Middleware ---

// IMPORTANT: CORS Configuration
const allowedOrigins = [
  'http://localhost:3000', // For your local development
  'https://landproperty-frontend.vercel.app' // Your deployed frontend
];

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  }
}));

app.use(express.json());

// --- Database Connection ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log('MongoDB connected successfully.'))
.catch(err => console.error('MongoDB connection error:', err));


// ===============================================
// --- MONGOOSE SCHEMAS & MODELS ---
// ===============================================

// 1. User Schema (For Login/Register)
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 6 },
});
UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});
UserSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};
const User = mongoose.model('User', UserSchema);

// 2. Owner Schema
const OwnerSchema = new mongoose.Schema({
    name: { type: String, required: true },
    contact: { type: String, required: true },
    email: { type: String, required: true },
    proofId: { type: String, required: true, unique: true },
});
const Owner = mongoose.model('Owner', OwnerSchema);

// 3. Land Schema
const LandSchema = new mongoose.Schema({
    location: { type: String, required: true },
    area: { type: String, required: true },
    marketValue: { type: Number, required: true },
    propertyType: { type: String, required: true },
    surveyNumber: { type: String, required: true, unique: true },
    currentOwner: { type: mongoose.Schema.Types.ObjectId, ref: 'Owner', required: true },
    ownershipHistory: [{
        owner: { type: mongoose.Schema.Types.ObjectId, ref: 'Owner' },
        transferDate: { type: Date, default: Date.now },
    }]
});
const Land = mongoose.model('Land', LandSchema);


// ===============================================
// --- API ENDPOINTS ---
// ===============================================

// --- Authentication Routes ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }
        user = new User({ email, password });
        await user.save();
        res.status(201).json({ msg: 'User registered successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        const payload = { user: { id: user.id, email: user.email } };
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// --- Land Registry API Routes ---
app.post('/api/registerOwner', async (req, res) => {
    try {
        const { name, contact, email, proofId } = req.body;
        if (!name || !contact || !email || !proofId) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        let owner = await Owner.findOne({ proofId });
        if (owner) {
            return res.status(400).json({ message: 'Owner with this Proof ID already exists.' });
        }
        const newOwner = new Owner({ name, contact, email, proofId });
        await newOwner.save();
        res.status(201).json({ message: 'Owner registered successfully!', owner: newOwner });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});
app.post('/api/registerLand', async (req, res) => {
    try {
        const { location, area, marketValue, propertyType, surveyNumber, currentOwnerId } = req.body;
        if (!location || !area || !marketValue || !propertyType || !surveyNumber || !currentOwnerId) {
            return res.status(400).json({ message: 'All fields are required.' });
        }
        const owner = await Owner.findById(currentOwnerId);
        if (!owner) {
            return res.status(404).json({ message: 'Owner not found. Please register the owner first.' });
        }
        let land = await Land.findOne({ surveyNumber });
        if (land) {
            return res.status(400).json({ message: 'Land with this Survey Number already exists.' });
        }
        const newLand = new Land({
            location, area, marketValue, propertyType, surveyNumber,
            currentOwner: currentOwnerId,
            ownershipHistory: [{ owner: currentOwnerId }]
        });
        await newLand.save();
        res.status(201).json({ message: 'Land registered successfully!', land: newLand });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 3. Transfer Ownership
app.put('/api/transferOwnership', async (req, res) => {
    try {
        const { landId, newOwnerId } = req.body;
        if (!landId || !newOwnerId) {
            return res.status(400).json({ message: 'Land ID and New Owner ID are required.' });
        }
        const land = await Land.findById(landId);
        if (!land) {
            return res.status(404).json({ message: 'Land not found.' });
        }
        const newOwner = await Owner.findById(newOwnerId);
        if (!newOwner) {
            return res.status(404).json({ message: 'New owner not found.' });
        }
        if (land.currentOwner.toString() === newOwnerId) {
            return res.status(400).json({ message: 'New owner cannot be the same as the current owner.' });
        }
        land.currentOwner = newOwnerId;
        land.ownershipHistory.push({ owner: newOwnerId });
        await land.save();
        res.status(200).json({ message: 'Ownership transferred successfully!', land });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// 4. Get Land Record and Ownership History
app.get('/api/getLandRecord/:landId', async (req, res) => {
    try {
        const land = await Land.findById(req.params.landId)
            .populate('currentOwner')
            .populate('ownershipHistory.owner');

        if (!land) {
            return res.status(404).json({ message: 'Land record not found.' });
        }
        res.status(200).json(land);
    } catch (error) {
        res.status(500).json({ message: 'Server error', error: error.message });
    }
});

// Helper routes to fetch all owners and lands for dropdowns
app.get('/api/getOwners', async (req, res) => {
    try {
        const owners = await Owner.find({}, 'name _id');
        res.status(200).json(owners);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.get('/api/getLands', async (req, res) => {
    try {
        const lands = await Land.find({}, 'location surveyNumber _id');
        res.status(200).json(lands);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// (I am omitting the duplicated route implementations for brevity, the code above is complete)


// --- Start Server ---
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));