const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const app = express();
// const PORT = 3000;


const SECRET_KEY = "YOUR_VERY_SECURE_SECRET_KEY_REPLACE_IN_PRODUCTION";

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    throw err;
  }
  console.log('Connected to MySQL database');
});

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Multer storage configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // Directory where images will be saved
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname); // Unique file name
  },
});

const upload = multer({ storage });

const recipeStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/resep/"); // Directory for recipe images
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const uploadRecipeImage = multer({ storage: recipeStorage });

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  try {
    const actualToken = token.split(' ')[1];
    const decoded = jwt.verify(actualToken, SECRET_KEY);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Unauthorized" });
  }
};


const generateUniqueCookpadId = async () => {
  let uniqueId = '';
  
  // Loop untuk mencari ID yang unik
  while (true) {
    // Generate ID acak, misalnya menggunakan angka acak dengan panjang 6 digit
    uniqueId = `@cook${Math.floor(100000 + Math.random() * 900000)}`;

    // Cek apakah ID acak sudah ada di database
    const checkIdQuery = 'SELECT * FROM users WHERE id_cookpad = ?';
    const [results] = await db.promise().query(checkIdQuery, [uniqueId]);

    if (results.length === 0) {
      // Jika ID tidak ditemukan di database, return ID unik
      break;
    }
  }

  return uniqueId;
};

app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  // Validation
  if (!username || !email || !password) {
    return res.status(400).json({ message: "All fields are required." });
  }

  try {
    const checkUserQuery = 'SELECT * FROM users WHERE email = ?';
    db.query(checkUserQuery, [email], async (checkErr, checkResults) => {
      if (checkErr) {
        return res.status(500).json({ message: "Database error" });
      }

      if (checkResults.length > 0) {
        return res.status(409).json({ message: "Email already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Generate unique id_cookpad
      const idCookpad = await generateUniqueCookpadId();

      const insertQuery = 'INSERT INTO users (username, email, password, id_cookpad) VALUES (?, ?, ?, ?)';
      db.query(insertQuery, [username, email, hashedPassword, idCookpad], (err, result) => {
        if (err) {
          return res.status(500).json({ message: "Error registering user" });
        }
        res.status(201).json({ message: "User registered successfully." });
      });
    });
  } catch (error) {
    res.status(500).json({ message: "Server error during registration" });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
      if (err) {
        return res.status(500).json({ message: "Database error" });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ message: "User not found." });
      }

      const user = results[0];

      const isPasswordValid = await bcrypt.compare(password, user.password);
      
      if (!isPasswordValid) {
        return res.status(401).json({ message: "Invalid credentials." });
      }

      const token = jwt.sign(
        { 
          id: user.id, 
          email: user.email, 
          username: user.username 
        }, 
        SECRET_KEY, 
        { expiresIn: "1h" }
      );

      res.status(200).json({ 
        message: "Login successful.", 
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          idCookpad: user.id_cookpad
        }
      });
    });
  } catch (error) {
    res.status(500).json({ message: "Server error during login" });
  }
});


// Add this route to your existing index.js file
app.get("/verify-token", (req, res) => {
  const token = req.headers['authorization'];
  
  if (!token) {
    return res.status(403).json({ message: "No token provided" });
  }

  try {
    const actualToken = token.split(' ')[1];
    const decoded = jwt.verify(actualToken, SECRET_KEY);
    
    // Log the user ID to the terminal
    console.log('User ID from Token:', decoded.id);
    
    res.status(200).json({ 
      userId: decoded.id,
    });
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
});

// Get Profile Route
app.get("/profile", verifyToken, (req, res) => {
  const query = 'SELECT id, username, email, id_cookpad, profile_picture FROM users WHERE id = ?';
  db.query(query, [req.userId], (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching profile" });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    
    res.status(200).json(results[0]);
  });
});

// Update Profile Route
app.put("/profile", verifyToken, (req, res) => {
  const { username, email, id_cookpad } = req.body;

  const query = 'UPDATE users SET username = ?, email = ?, id_cookpad = ? WHERE id = ?';
  
  db.query(query, [username, email, id_cookpad, req.userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error updating profile" });
    }
    
    res.status(200).json({ 
      message: "Profile updated successfully",
      user: { username, email, id_cookpad }
    });
  });
});

// Profile Picture Upload Route
app.post("/upload-profile-picture", verifyToken, upload.single("profilePicture"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  const filePath = req.file.path.replace("\\", "/"); // Handle Windows paths
  const updateQuery = "UPDATE users SET profile_picture = ? WHERE id = ?";

  db.query(updateQuery, [filePath, req.userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: "Error saving profile picture" });
    }

    res.status(200).json({
      message: "Profile picture uploaded successfully",
      filePath,
    });
  });
});

//add recipe
app.post("/addRecipe", verifyToken, (req, res) => {
  const { title, servings, cookTime, ingredients, steps } = req.body;

  if (!title || !ingredients || !steps) {
    return res.status(400).json({ message: "Required fields are missing." });
  }

  const query = `
    INSERT INTO ownresep (user_id, title, servings, cook_time, ingredients, steps, image_path)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [
      req.userId,
      title,
      servings || null,
      cookTime || null,
      JSON.stringify(ingredients),
      JSON.stringify(steps),
      req.body.imagePath || null,
    ],
    (err, result) => {
      if (err) {
        return res.status(500).json({ message: "Failed to save recipe." });
      }
      res.status(201).json({ message: "Recipe added successfully." });
    }
  );
});

app.post("/upload-recipe-image", verifyToken, uploadRecipeImage.single("recipeImage"), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  const filePath = req.file.path.replace("\\", "/"); // Handle Windows paths
  res.status(200).json({
    message: "Recipe image uploaded successfully",
    filePath,
  });
});


app.get('/user/own-recipes', verifyToken, async (req, res) => {
  const userId = req.userId;

  try {
    const [rows] = await db.promise().query(
      'SELECT id, title, servings, cook_time, REPLACE(image_path, "uploads/", "") AS image_path FROM ownresep WHERE user_id = ?',
      [userId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching own recipes', error });
  }
});


app.get("/favresep", (req, res) => {
  const query = 'SELECT id, user_id, title, servings, cook_time, ingredients, steps, created_at, image_path FROM favresep';

  db.query(query, (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching favorite recipes" });
    }

    // Check if there are no records
    if (results.length === 0) {
      return res.status(404).json({ message: "No favorite recipes found" });
    }

    res.status(200).json(results);
  });
});

app.get('/user/favorite-recipes', verifyToken, async (req, res) => {
  const userId = req.userId;

  try {
    const [rows] = await db.promise().query(
      `SELECT r.id, o.title, REPLACE(o.image_path, 'uploads/', '') AS image_path 
       FROM favresep f
       JOIN resep r ON f.resep_id = r.id
       JOIN ownresep o ON r.ownresep_id = o.id
       WHERE f.user_id = ?`,
      [userId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching favorite recipes', error });
  }
});

app.get('/user/published-recipes', verifyToken, async (req, res) => {
  const userId = req.userId;

  try {
    const [rows] = await db.promise().query(
      `SELECT r.id, o.title, REPLACE(o.image_path, 'uploads/', '') AS image_path 
       FROM resep r
       JOIN ownresep o ON r.ownresep_id = o.id
       WHERE o.user_id = ?`,
      [userId]
    );
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching published recipes', error });
  }
});

app.get('/user/recipe-detail/:source/:id', verifyToken, async (req, res) => {
  const { source, id } = req.params;
  const userId = req.userId;

  console.log('User ID:', userId);
  console.log('Source:', source);
  console.log('Recipe ID:', id);

  let query = '';
  let params = [userId, id];

  // Tentukan query berdasarkan source
  if (source === 'own') {
    query = `SELECT id, title, servings, cook_time, ingredients, steps, 
             REPLACE(image_path, 'uploads/', '') AS image_path 
             FROM ownresep WHERE user_id = ? AND id = ?`;
  } else if (source === 'favorite') {
    query = `SELECT r.id, o.title, o.servings, o.cook_time, o.ingredients, o.steps, 
             REPLACE(o.image_path, 'uploads/', '') AS image_path 
             FROM favresep f
             JOIN resep r ON f.resep_id = r.id
             JOIN ownresep o ON r.ownresep_id = o.id
             WHERE f.user_id = ? AND r.id = ?`;
  } else if (source === 'published') {
    query = `SELECT r.id, o.title, o.servings, o.cook_time, o.ingredients, o.steps, 
             REPLACE(o.image_path, 'uploads/', '') AS image_path 
             FROM resep r
             JOIN ownresep o ON r.ownresep_id = o.id
             WHERE o.user_id = ? AND r.id = ?`;
  } else {
    return res.status(400).json({ message: 'Invalid source' });
  }

  try {
    const [rows] = await db.promise().query(query, params);
    if (rows.length === 0) {
      return res.status(404).json({ message: 'Recipe not found' });
    }
    res.json(rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching recipe details', error });
  }
});

app.get('/recipes', async (req, res) => {
  const searchKeyword = req.query.search || '';  // Ambil keyword pencarian
  try {
    const [rows] = await db.promise().query(
      `SELECT r.id, o.title, o.servings, o.cook_time, 
              REPLACE(o.image_path, 'uploads/', '') AS image_path, 
              o.user_id, o.ingredients, o.steps, 
              u.username
       FROM resep r
       JOIN ownresep o ON r.ownresep_id = o.id
       JOIN users u ON o.user_id = u.id
       WHERE o.title LIKE ? 
       OR JSON_CONTAINS(o.ingredients, JSON_QUOTE(?))`,
      [`%${searchKeyword}%`, searchKeyword]
    );

    res.json(rows);  // Kembalikan hasil pencarian
  } catch (error) {
    res.status(500).json({ message: 'Error fetching recipes', error });
  }
});


app.post('/user/share-recipe/:id', (req, res) => {
  const { id } = req.params;
  const { userId } = req.body;

  // Pastikan userId ada dan tidak null
  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  const query = 'INSERT INTO resep (user_id, ownresep_id) VALUES (?, ?)';
  db.query(query, [userId, id], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error sharing recipe', error: err });
    }
    res.status(200).json({ message: 'Recipe shared successfully', data: result });
  });
});


app.delete('/user/delete-recipe/:id', (req, res) => {
  const { id } = req.params;
  const { userId } = req.body;  // Pastikan kita menerima userId di body request

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });  // Validasi userId
  }

  // Query untuk menghapus resep berdasarkan ID dan userId
  const query = 'DELETE FROM ownresep WHERE id = ? AND user_id = ?';
  db.query(query, [id, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error deleting recipe', error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Recipe not found or not owned by this user' });
    }
    res.status(200).json({ message: 'Recipe deleted successfully' });
  });
});



app.delete('/user/unshare-recipe/:id', (req, res) => {
  const { id } = req.params;
  const { userId } = req.body;

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  // Hapus data dari tabel resep berdasarkan ID yang sesuai
  const query = 'DELETE FROM resep WHERE id = ? AND user_id = ?';
  db.query(query, [id, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error unsharing recipe', error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Recipe not found or not shared by this user' });
    }

    res.status(200).json({ message: 'Recipe unshared successfully' });
  });
});

app.delete('/user/unfav-recipe/:id', (req, res) => {
  const { id } = req.params; // id is the resep_id that will be unfav
  const { userId } = req.body; // userId from the body of the request

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  // Delete from the favresep table based on both resep_id and user_id
  const query = 'DELETE FROM favresep WHERE resep_id = ? AND user_id = ?'; // Use both resep_id and user_id
  db.query(query, [id, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Error unfav recipe', error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Recipe not found or not favorited by this user' });
    }

    res.status(200).json({ message: 'Recipe unfav successfully' });
  });
});


app.post('/user/fav-recipe', (req, res) => {
  const { userId, resepId } = req.body;

  if (!userId || !resepId) {
    return res.status(400).json({ message: 'User ID and Recipe ID are required' });
  }

  const query = 'INSERT INTO favresep (user_id, resep_id) VALUES (?, ?)';
  db.query(query, [userId, resepId], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ message: 'Recipe already favorited' });
      }
      return res.status(500).json({ message: 'Database error', error: err });
    }
    res.status(200).json({ message: 'Recipe added to favorites successfully' });
  });
});

// **Hapus resep dari favorit**
app.delete('/user/unfav-recipee/:id', (req, res) => {
  const { id } = req.params; // ID resep
  const userId = req.query.userId; // User ID dari query parameter

  if (!userId) {
    return res.status(400).json({ message: 'User ID is required' });
  }

  const query = 'DELETE FROM favresep WHERE resep_id = ? AND user_id = ?';
  db.query(query, [id, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Database error', error: err });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Recipe not found in favorites' });
    }
    res.status(200).json({ message: 'Recipe removed from favorites successfully' });
  });
});


// **Cek status favorit**
app.get('/user/check-fav-recipe/:id', (req, res) => {
  const { id } = req.params; // ID resep
  const userId = req.query.userId; // User ID dari query parameter

  if (!userId) {
    return res.status(400).json({ message: 'User ID is requiredeeeeee' });
  }

  const query = 'SELECT * FROM favresep WHERE resep_id = ? AND user_id = ?';
  db.query(query, [id, userId], (err, result) => {
    if (err) {
      return res.status(500).json({ message: 'Database error', error: err });
    }
    res.status(200).json({ isFavorited: result.length > 0 });
  });
});



app.put("/editRecipe/:id", verifyToken, upload.single('image'), (req, res) => {
  const { title, servings, cookTime, ingredients, steps, existingImagePath } = req.body;
  const recipeId = req.params.id;

  // Debug logging
  console.log('Existing Image Path:', existingImagePath);
  console.log('New Uploaded File:', req.file);

  // Tentukan path image
  let newImagePath = existingImagePath; // Default ke path existing

  // Jika ada file baru diupload, gunakan filename baru
  if (req.file) {
    newImagePath = req.file.filename;
  }

  // Validasi input
  if (!title || !ingredients || !steps) {
    return res.status(400).json({ message: "Required fields are missing" });
  }

  const query = `
    UPDATE ownresep
    SET 
      title = ?, 
      servings = ?, 
      cook_time = ?, 
      ingredients = ?, 
      steps = ?, 
      image_path = ?
    WHERE id = ? AND user_id = ?
  `;

  // Tambahkan prefix 'uploads/' jika path tidak kosong
  const fullImagePath = newImagePath ? `uploads/${newImagePath}` : null;

  db.query(
    query,
    [
      title,
      servings || null,
      cookTime || null,
      JSON.stringify(JSON.parse(ingredients)),
      JSON.stringify(JSON.parse(steps)),
      fullImagePath, // Gunakan path lengkap atau null
      recipeId,
      req.userId,
    ],
    (err, result) => {
      if (err) {
        console.error('Update Recipe Error:', err);
        return res.status(500).json({ message: "Failed to update recipe", error: err });
      }
      
      if (result.affectedRows === 0) {
        return res.status(404).json({ message: "Recipe not found or you're not authorized" });
      }
      
      res.status(200).json({ 
        message: "Recipe updated successfully",
        imagePath: newImagePath 
      });
    }
  );
});


module.exports = app;

// Serve static files (uploads directory)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

