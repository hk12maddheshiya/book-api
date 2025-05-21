import express from 'express';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import schema from './signupSchema.js';

dotenv.config();
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Generate JWT token for a given email, expires in 1 hour
function jwtToken(email) {
  return jwt.sign({ email }, process.env.JWT_KEY, { expiresIn: '1h' });
}

// POST /login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ message: 'Invalid Credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid Credentials' });

    const token = jwtToken(email);
    res.setHeader('Authorization', `Bearer ${token}`);
    return res.status(200).json({ token, message: 'Login Successful' });
  } catch (err) {
    return res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// POST /signup
app.post('/signup', async (req, res) => {
  const parseResult = await schema.safeParse(req.body);
  if (!parseResult.success) {
    return res.status(400).json({ message: 'Invalid input', errors: parseResult.error.format() });
  }

  const { email, password, name } = parseResult.data;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await prisma.user.create({ data: { email, password: hashedPassword, name } });
    return res.status(201).json({ message: 'Signup successful' });
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }
});

// Auth middleware
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: 'Authorization header missing' });

    const [scheme, token] = authHeader.split(' ');
    if (scheme !== 'Bearer' || !token) {
      return res.status(401).json({ message: 'Invalid token format' });
    }

    const { email } = jwt.verify(token, process.env.JWT_KEY);
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ message: 'User not found' });

    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Unauthorized', error: err.message });
  }
};

// POST /books (protected)
app.post('/books', authenticate, async (req, res) => {
  const { title, author, genre } = req.body;
  if (!title || !author || !genre) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const addedById = req.user.id;
    const book = await prisma.book.create({ data: { title, author, genre, addedById } });
    res.status(201).json({ message: 'Book added', book });
  } catch (err) {
    res.status(500).json({ message: 'Failed to add book', error: err.message });
  }
});

// GET /books with pagination
app.get('/books', async (req, res) => {
  const page = parseInt(req.query.page) || 0;
  const limit = parseInt(req.query.limit) || 10;

  try {
    const books = await prisma.book.findMany({ skip: page * limit, take: limit });
    res.status(200).json(books);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching books', error: err.message });
  }
});

// GET /books/:id
app.get('/books/:id', async (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) {
    return res.status(400).json({ message: 'Invalid book ID' });
  }

  try {
    const book = await prisma.book.findUnique({ where: { id }, include: { reviews: true } });
    if (!book) return res.status(404).json({ message: 'Book not found' });
    res.json(book);
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// POST /books/:id/reviews 
app.post('/books/:id/reviews', authenticate, async (req, res) => {
  const bookId = parseInt(req.params.id);
  const { rating, comment } = req.body;
  const userId = req.user.id;

  if (!bookId || !rating) {
    return res.status(400).json({ message: 'Missing required fields (rating, bookId)' });
  }

  try {
    const review = await prisma.review.create({ data: { rating: parseInt(rating), comment: comment || null, userId, bookId } });
    res.status(201).json({ message: 'Review added', review });
  } catch (err) {
    res.status(500).json({ message: 'Error adding review', error: err.message });
  }
});

// PUT /reviews/:id (protected)
app.put('/reviews/:id', authenticate, async (req, res) => {
  const id = parseInt(req.params.id);
  const { rating, comment } = req.body;

  try {
    const review = await prisma.review.update({ where: { id }, data: { rating, comment } });
    res.json({ message: 'Review updated', review });
  } catch (err) {
    res.status(500).json({ message: 'Error updating review', error: err.message });
  }
});

// DELETE /reviews/:id (protected)
app.delete('/reviews/:id', authenticate, async (req, res) => {
  const id = parseInt(req.params.id);

  try {
    await prisma.review.delete({ where: { id } });
    res.json({ message: 'Review deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting review', error: err.message });
  }
});

// GET /search
// GET /search
app.get('/search', async (req, res) => {
  const q = req.query.q || '';  // default to empty string if not provided

  try {
    const books = await prisma.book.findMany({
      where: {
        OR: [
          { title: { contains: q, mode: 'insensitive' } },
          { author: { contains: q, mode: 'insensitive' } }
        ]
      }
    });
   
    res.status(200).json(books);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Search failed', error: err.message });
  }
});

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
