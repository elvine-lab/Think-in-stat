const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const methodOverride = require('method-override');
const fs = require('fs');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 6030;

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => console.log('✅ Connected to MongoDB'));

// Mongoose Models
const User = mongoose.model('User', new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
}));

const Post = mongoose.model('Post', new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  file_url: { type: String },
  topic: { type: String },
  reading_time: { type: Number },
  created_at: { type: Date, default: Date.now },
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
}));

const Topic = mongoose.model('Topic', new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  slug: { type: String, required: true, unique: true },
  created_at: { type: Date, default: Date.now }
}));

// Middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(methodOverride('_method'));

app.use(session({
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'sessions'
  }),
  secret: process.env.SESSION_SECRET || 'statistician_blog_secret_2606',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

// Custom middleware
const isAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.email === process.env.ADMIN_EMAIL) {
    return next();
  }
  req.flash('error', 'Unauthorized access');
  res.redirect('/');
};

app.use((req, res, next) => {
  res.locals.messages = req.flash();
  res.locals.isAdmin = req.isAuthenticated() && req.user.email === process.env.ADMIN_EMAIL;
  res.locals.showLogin = process.env.SHOW_LOGIN === 'true';
  next();
});

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = 'uploads/';
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

// Helper functions
function calculateReadingTime(text) {
  const wordsPerMinute = 200;
  const wordCount = text.replace(/<[^>]*>/g, '').split(/\s+/).length;
  return Math.max(1, Math.ceil(wordCount / wordsPerMinute));
}

function generateSlug(name) {
  return name.toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/--+/g, '-')
    .trim();
}

// Passport configuration
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  try {
    if (email !== process.env.ADMIN_EMAIL) {
      return done(null, false, { message: 'Access restricted' });
    }

    const user = await User.findOne({ email });
    if (!user) return done(null, false, { message: 'User not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return done(null, false, { message: 'Incorrect password' });

    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Database initialization
async function initializeDatabase() {
  try {
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    const adminName = process.env.ADMIN_NAME || 'Bernard Odhiambo';

    if (!adminEmail || !adminPassword) {
      throw new Error('Admin credentials not configured in environment variables');
    }

    const existingUser = await User.findOne({ email: adminEmail });
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      await User.create({
        email: adminEmail,
        password: hashedPassword,
        name: adminName
      });
      console.log(`✅ Admin user created: ${adminEmail}`);
    }
  } catch (err) {
    console.error('Database initialization error:', err);
    throw err;
  }
}

// Routes
app.get('/', async (req, res) => {
  try {
    const posts = await Post.aggregate([
      {
        $lookup: {
          from: 'users',
          localField: 'user_id',
          foreignField: '_id',
          as: 'author'
        }
      },
      { $unwind: '$author' },
      {
        $project: {
          _id: 1,
          id: { $toString: '$_id' },
          title: 1,
          content: 1,
          file_url: 1,
          topic: 1,
          reading_time: 1,
          created_at: 1,
          author_name: '$author.name'
        }
      },
      { $sort: { created_at: -1 } }
    ]);
    
    const topics = await Topic.find({}, 'name slug').sort('name');
    
    res.render('index', { 
      posts,
      topics
    });
  } catch (err) {
    console.error('Error fetching posts:', err);
    req.flash('error', 'Failed to load posts');
    res.redirect('/');
  }
});

app.get('/about', (req, res) => {
  res.render('about');
});

app.get('/login', (req, res) => {
  if (process.env.SHOW_LOGIN !== 'true') {
    return res.redirect('/');
  }
  if (req.isAuthenticated()) {
    return res.redirect('/dashboard');
  }
  res.render('login', { message: req.flash('error') });
});

app.post('/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: true,
  })
);

app.get('/logout', (req, res) => {
  req.logout(() => {
    req.flash('success', 'You have been logged out');
    res.redirect('/');
  });
});

app.get('/dashboard', isAdmin, async (req, res) => {
  try {
    const posts = await Post.find({ user_id: req.user._id }).sort({ created_at: -1 });
    const topics = await Topic.find({}, '_id name slug').sort('name');
    
    // Convert to include id field for template compatibility
    const formattedPosts = posts.map(post => ({
      ...post.toObject(),
      id: post._id.toString()
    }));
    
    res.render('dashboard', { 
      posts: formattedPosts,
      topics
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    req.flash('error', 'Failed to load dashboard');
    res.redirect('/');
  }
});

app.get('/new-post', isAdmin, async (req, res) => {
  try {
    const topics = await Topic.find({}, 'name').sort('name');
    res.render('new-post', { topics: topics.map(t => t.name) });
  } catch (err) {
    console.error('Error fetching topics:', err);
    req.flash('error', 'Failed to load topics');
    res.redirect('/dashboard');
  }
});

app.post('/upload-image', isAdmin, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image uploaded' });
  }
  res.json({ 
    success: true, 
    filePath: `/uploads/${req.file.filename}` 
  });
});

app.post('/new-post', isAdmin, upload.single('file'), async (req, res) => {
  try {
    const { title, content, topic } = req.body;
    if (!title || !content || !topic) {
      req.flash('error', 'Title, content, and topic are required');
      return res.redirect('/new-post');
    }

    const file_url = req.file ? `/uploads/${req.file.filename}` : null;
    const reading_time = calculateReadingTime(content);

    await Post.create({
      title,
      content,
      file_url,
      topic,
      reading_time,
      user_id: req.user._id
    });
    
    req.flash('success', 'Post created successfully');
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Post creation error:', err);
    req.flash('error', 'Failed to create post: ' + err.message);
    res.redirect('/new-post');
  }
});

app.post('/add-topic', isAdmin, async (req, res) => {
  try {
    const { topic } = req.body;
    if (!topic) {
      req.flash('error', 'Topic name is required');
      return res.redirect('/dashboard');
    }

    const slug = generateSlug(topic);
    await Topic.findOneAndUpdate(
      { name: topic },
      { name: topic, slug },
      { upsert: true, new: true }
    );
    
    req.flash('success', 'Topic added successfully');
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Topic creation error:', err);
    req.flash('error', 'Failed to add topic');
    res.redirect('/dashboard');
  }
});

app.post('/delete-topic/:id', isAdmin, async (req, res) => {
  try {
    const topic = await Topic.findById(req.params.id);
    if (!topic) {
      req.flash('error', 'Topic not found');
      return res.redirect('/dashboard');
    }

    const postsWithTopic = await Post.findOne({ topic: topic.name });
    if (postsWithTopic) {
      req.flash('error', 'Cannot delete topic - there are posts associated with it');
      return res.redirect('/dashboard');
    }

    await Topic.findByIdAndDelete(req.params.id);
    req.flash('success', 'Topic deleted successfully');
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Delete topic error:', err);
    req.flash('error', 'Failed to delete topic');
    res.redirect('/dashboard');
  }
});

app.get('/topic/:slug', async (req, res) => {
  try {
    const topic = await Topic.findOne({ slug: req.params.slug });
    if (!topic) {
      req.flash('error', 'Topic not found');
      return res.redirect('/');
    }
    
    const posts = await Post.aggregate([
      { $match: { topic: topic.name } },
      {
        $lookup: {
          from: 'users',
          localField: 'user_id',
          foreignField: '_id',
          as: 'author'
        }
      },
      { $unwind: '$author' },
      {
        $project: {
          _id: 1,
          id: { $toString: '$_id' },
          title: 1,
          content: 1,
          file_url: 1,
          topic: 1,
          reading_time: 1,
          created_at: 1,
          author_name: '$author.name'
        }
      },
      { $sort: { created_at: -1 } }
    ]);
    
    const topics = await Topic.find({}, 'name slug').sort('name');
    
    res.render('topic', {
      topic: topic.name,
      posts,
      topics,
      isAdmin: res.locals.isAdmin,
      showLogin: res.locals.showLogin
    });
  } catch (err) {
    console.error('Topic view error:', err);
    req.flash('error', 'Failed to load topic');
    res.redirect('/');
  }
});

app.get('/post/:id', async (req, res) => {
  try {
    const post = await Post.aggregate([
      { $match: { _id: new mongoose.Types.ObjectId(req.params.id) } },
      {
        $lookup: {
          from: 'users',
          localField: 'user_id',
          foreignField: '_id',
          as: 'author'
        }
      },
      { $unwind: '$author' },
      {
        $project: {
          _id: 1,
          id: { $toString: '$_id' },
          title: 1,
          content: 1,
          file_url: 1,
          topic: 1,
          reading_time: 1,
          created_at: 1,
          author_name: '$author.name'
        }
      }
    ]);

    if (post.length === 0) {
      req.flash('error', 'Post not found');
      return res.redirect('/');
    }

    const relatedPosts = await Post.find({
      topic: post[0].topic || 'General',
      _id: { $ne: new mongoose.Types.ObjectId(req.params.id) }
    })
    .sort({ created_at: -1 })
    .limit(2)
    .lean();

    const topics = await Topic.find({}, 'name slug').sort('name');

    res.render('post', { 
      post: post[0],
      relatedPosts,
      topics
    });
  } catch (err) {
    console.error('Post view error:', err);
    req.flash('error', 'Failed to load post');
    res.redirect('/');
  }
});

app.get('/edit-post/:id', isAdmin, async (req, res) => {
  try {
    const post = await Post.findOne({
      _id: req.params.id,
      user_id: req.user._id
    });
    
    if (!post) {
      req.flash('error', 'Post not found or unauthorized');
      return res.redirect('/dashboard');
    }

    const topics = await Topic.find({}, 'name').sort('name');

    res.render('edit-post', { 
      post,
      topics: topics.map(t => t.name)
    });
  } catch (err) {
    console.error('Edit post error:', err);
    req.flash('error', 'Failed to load post for editing');
    res.redirect('/dashboard');
  }
});

app.post('/edit-post/:id', isAdmin, upload.single('file'), async (req, res) => {
  try {
    const { title, content, topic } = req.body;
    if (!title || !content || !topic) {
      req.flash('error', 'Title, content, and topic are required');
      return res.redirect(`/edit-post/${req.params.id}`);
    }

    const reading_time = calculateReadingTime(content);
    let file_url = req.body.existing_file;

    if (req.file) {
      file_url = `/uploads/${req.file.filename}`;
      if (req.body.existing_file) {
        try {
          const oldFilePath = path.join(__dirname, 'public', req.body.existing_file);
          fs.unlinkSync(oldFilePath);
        } catch (err) {
          console.error('Error deleting old image:', err);
        }
      }
    }

    await Post.findByIdAndUpdate(req.params.id, {
      title,
      content,
      file_url,
      topic,
      reading_time
    });
    
    req.flash('success', 'Post updated successfully');
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Post update error:', err);
    req.flash('error', 'Failed to update post');
    res.redirect(`/edit-post/${req.params.id}`);
  }
});

app.post('/delete-post/:id', isAdmin, async (req, res) => {
  try {
    const post = await Post.findOneAndDelete({
      _id: req.params.id,
      user_id: req.user._id
    });
    
    if (!post) {
      req.flash('error', 'Post not found or unauthorized');
      return res.redirect('/dashboard');
    }

    if (post.file_url) {
      try {
        const filePath = path.join(__dirname, 'public', post.file_url);
        fs.unlinkSync(filePath);
      } catch (err) {
        console.error('Error deleting image file:', err);
      }
    }

    req.flash('success', 'Post deleted successfully');
    res.redirect('/dashboard');
  } catch (err) {
    console.error('Delete error:', err);
    req.flash('error', 'Failed to delete post');
    res.redirect('/dashboard');
  }
});

// Start server
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(port, () => {
      console.log(`🚀 Server running at http://localhost:${port}`);
      console.log(`🔒 Login ${process.env.SHOW_LOGIN === 'true' ? 'enabled' : 'disabled'}`);
    });
  } catch (err) {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  }
}

startServer();