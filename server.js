const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');


// MongoDB Connection

mongoose.connect('mongodb://localhost:27017/mydb')
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log('Error:', err));

// Event Schema
const eventSchema = new mongoose.Schema({
  eventName: String,
  venue: String,
  eventDate: Date,
  startTime: String,
  endTime: String,
  chiefGuest: String,
  conductedBy: String,
});

const Event = mongoose.model('Event', eventSchema);

const app = express();
app.use(cors());
app.use(bodyParser.json());

// POST route to save event
app.post('/create-event', async (req, res) => {
  const newEvent = new Event(req.body);

  try {
    await newEvent.save();
    res.status(201).send('Event created successfully!');
  } catch (err) {
    res.status(500).send('Error creating event: ' + err.message);
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


app.get('/get-events', async (req, res) => {
  try {
    const events = await Event.find();  
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching events' });
  }
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




// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const UserModel = mongoose.model('User', userSchema);

// Signup route
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  // Check if user already exists
  const existingUser = await UserModel.findOne({ email });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create new user
  const newUser = new UserModel({ email, password: hashedPassword });
  newUser
  .save()
  .then((newUser) => res.status(201).json({ message: 'User created successfully' }))
  .catch((err) => res.status(500).json({ error: 'Error in signup process', err }));
  
  
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await UserModel.findOne({ email });
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