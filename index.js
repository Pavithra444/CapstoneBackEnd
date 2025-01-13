const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
require("dotenv").config();


const app = express();

// Setup CORS, body parser, and serve static files
app.use(cors());
app.use(bodyParser.json());

// Ensure the uploads folder exists
const fs = require('fs');
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure Multer storage and file upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir); // Save files to the 'uploads' folder
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  },
});

const upload = multer({ 
  storage: storage,
  fileFilter: (req, file, cb) => {
    // File validation - only images allowed
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Invalid file type. Only JPEG, PNG, and GIF allowed.'));
    }
    cb(null, true);
  }
});

// MongoDB connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('Error:', err));

// Check if MONGO_URI is set
if (!process.env.MONGO_URI) {
  console.error('MONGO_URI environment variable is not set.');
  process.exit(1); // Exit if MongoDB URI is missing
}

// Define Event Schema
const eventSchema = new mongoose.Schema({
  eventId: { type: String, required: true, unique: true },
  eventName: { type: String, required: true },
  venue: { type: String, required: true },
  eventDate: { type: Date, required: true },
  startTime: { type: String, required: true },
  endTime: { type: String, required: true },
  chiefGuest: { type: String, required: true },
  conductedBy: { type: String, required: true },
  eventDesc: { type: String, required: true },
  referenceImage: { type: String, required: true },
  special: { type: Number, required: true },
  vip: { type: Number, required: true },
  general: { type: Number, required: true },
  attendees: { type: Number, required: true },
 
});
const Event = mongoose.model('Event', eventSchema);

// Create Event Route (POST)
app.post('/create-event', upload.single('referenceImage'), async (req, res) => {
  try {
    // Extract uploaded file path if exists
    const referenceImagePath = req.file ? '/uploads/' + req.file.filename : null;

    const requiredFields = [
      'eventId', 'eventName', 'venue', 'eventDate', 'startTime', 'endTime',
      'chiefGuest', 'conductedBy', 'eventDesc','special', 'vip', 'general', 'attendees'
    ];

    const missingFields = [];
    for (const field of requiredFields) {
      if (!req.body[field] && field !== 'referenceImage' && !referenceImagePath) {
        missingFields.push(field);
      }
    }

    // If there are missing fields, return an error response
    if (missingFields.length > 0) {
      return res.status(400).json({
        message: 'Missing required fields',
        missingFields: missingFields,
      });
    }

    // Prepare event data
    const newEvent = new Event({
      ...req.body,   // Get other fields from the request body
      referenceImage: referenceImagePath, // Save the image file path
    });

    // Save event data to MongoDB
    await newEvent.save();
    res.status(201).send('Event created successfully!');
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).send('Error creating event: ' + err.message);
    
  }
});

// Serve static files (e.g., images) from the 'uploads' folder
app.use('/uploads', express.static('uploads'));

// Get All Events
app.get('/get-events', async (req, res) => {
  try {
    // Destructure filter parameters from the query string
    const { date, venue, special, vip, general } = req.query;

    // Build the filter object based on provided query parameters
    const filter = {};

    if (date) {
      // Assuming eventDate is a Date field in the database
      filter.eventDate = { $eq: new Date(date) }; // Filter events by exact date
    }

    if (venue) {
      filter.venue = { $regex: venue, $options: 'i' }; // Case-insensitive search for venue
    }

    if (special) {
      filter.special = { $eq: special }; // Filter by special ticket availability
    }

    if (vip) {
      filter.vip = { $eq: vip }; // Filter by VIP ticket availability
    }

    if (general) {
      filter.general = { $eq: general }; // Filter by general ticket availability
    }

    const events = await Event.find(filter);
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching events' });
  }
});


app.get('/get-event/:eventId', async (req, res) => {
  try {
    const event = await Event.findOne({ eventId: req.params.eventId }); // Search by custom eventId
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.json(event);
  } catch (err) {
    console.error('Error fetching event:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
// PUT route to update event details
app.put('/update-event/:eventId', async (req, res) => {
  try {
    const event = await Event.findOneAndUpdate({ eventId: req.params.eventId }, req.body, { new: true }); // Search by custom eventId
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.json(event); // Return updated event
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/delete-event/:eventId', async (req, res) => {
  try {
    const event = await Event.findOneAndDelete({ eventId: req.params.eventId }); // Search by custom eventId
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.json({ message: 'Event deleted successfully' });
  } catch (err) {
    console.error('Error deleting event:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/get-event-pricedtls/:eventName', async (req, res) => {
  try {
    const event = await Event.findOne({ eventName: req.params.eventName }); 
    if (!event) {
      return res.status(404).json({ message: 'Event not found' });
    }
    res.json({ success: true, event });
  } catch (err) {
    console.error('Error fetching event:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


//************************* */
// // User Schema
// const userSchema = new mongoose.Schema({
//   email: { type: String, required: true, unique: true },
//   password: { type: String, required: true },
// });
// const UserModel = mongoose.model('User', userSchema);

// // Signup Route
// app.post('/signup', async (req, res) => {
//   const { email, password } = req.body;

//   // Check if user already exists
//   const existingUser = await UserModel.findOne({ email });
//   if (existingUser) {
//     return res.status(400).json({ message: 'User already exists' });
//   }

//   // Hash the password
//   const hashedPassword = await bcrypt.hash(password, 10);

//   // Create new user
//   const newUser = new UserModel({ email, password: hashedPassword });
//   try {
//     await newUser.save();
//     res.status(201).json({ message: 'User created successfully' });
//   } catch (err) {
//     res.status(500).json({ error: 'Error in signup process', err });
//   }
// });
//**************************** */
// User Schema and Model
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// Signup route
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  // Input validation
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  // Check if email is valid
  const emailRegex = /\S+@\S+\.\S+/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  // Check if password meets requirements (e.g., at least 6 characters)
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  try {
    // Check if the user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'Email or username already taken' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    // Save the new user to the database
    await newUser.save();

    // Send success response
    res.status(201).json({ message: 'User registered successfully' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});
// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Compare password
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Generate JWT token
  const token = jwt.sign({ id: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
  res.json({ message: 'Login successful', token });
});

// Global Error Handlers
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled Rejection:', err);
  process.exit(1);
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


// Event Attendee Schema
const attendeeSchema = new mongoose.Schema({
  name: String,
  mailId: String,
  password: String,
  phoneNo: String,
  addressLine1: String,
  addressLine2: String,
  city: String,
  pincode: String,
  state: String,
  country: String,
  event: String,
  registrationId: String,
  registrationDate: String,
});

const Attendee = mongoose.model('Attendee', attendeeSchema);

// POST endpoint to save form data
app.post('/register', (req, res) => {
  const {
    name,
    mailId,
    password,
    phoneNo,
    addressLine1,
    addressLine2,
    city,
    pincode,
    state,
    country,
    event,
    registrationId,
    registrationDate,
  } = req.body;

  const newAttendee = new Attendee({
    name,
    mailId,
    password,
    phoneNo,
    addressLine1,
    addressLine2,
    city,
    pincode,
    state,
    country,
    event,
    registrationId,
    registrationDate,
  });

  newAttendee
    .save()
    .then((attendee) => res.status(201).json({ message: 'Attendee registered successfully', attendee }))
    .catch((err) => res.status(500).json({ error: 'Error saving attendee data', err }));
});


// Attendee Registration list fetch
app.get('/get-regdetails', async (req, res) => {
  try {
    const reg = await Attendee.find();  // Get all events from the database
    res.json(reg);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching registration details' });
  }
});


// API to fetch attendee details by registrationId
app.post('/get-attendee-details', async (req, res) => {
  const { registrationId } = req.body;

  try {
    const attendee = await Attendee.findOne({ registrationId });

    if (attendee) {
      res.status(200).json({ success: true, attendee });
    } else {
      res.status(404).json({ success: false, message: 'Attendee not found' });
    }
  } catch (error) {
    console.error('Error fetching attendee details:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

const ticketSchema = new mongoose.Schema({
  registrationId: { type: String, required: true },
  name: { type: String, required: true },
  phoneNo: { type: String, required: true },
  eventName: { type: String, required: true },
  ticketCategory: { type: String, required: true },
  ticketPrice: { type: Number, required: true },
  ticketDate:  { type: Date, required: true },
});

const Ticket = mongoose.model('Ticket', ticketSchema);

app.post('/generate-ticket', async (req, res) => {
  const { registrationId, name, phoneNo, eventName, ticketCategory, ticketPrice,ticketDate} = req.body;

  if (!registrationId || !name || !phoneNo || !eventName || !ticketCategory || !ticketPrice) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }
  if (!ticketDate || isNaN(Date.parse(ticketDate))) {
    return res.status(400).json({ success: false, message: 'Invalid ticket date' });
  }
  

  const ticket = new Ticket({
    registrationId,
    name,
    phoneNo,
    eventName,
    ticketCategory,
    ticketPrice,
    ticketDate,
  });

    ticket
    .save()
    .then((ticket) => res.status(201).json({ message: 'Ticket generated successfully', ticket }))
    .catch((err) => res.status(500).json({ error: 'Error saving ticket data', err }));
});


app.get('/tickets/:registrationId', async (req, res) => {
  const { registrationId } = req.params;

  try {
    // Fetch ticket data by registration ID from MongoDB
    const ticket = await Ticket.findOne({ registrationId });
    
    if (!ticket) {
      return res.status(404).json({ message: 'Ticket not found' });
    }

    // Return ticket details
    res.status(200).json(ticket);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});