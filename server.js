const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const { promisify } = require('util');
const mkdir = promisify(fs.mkdir);
const mime = require('mime-types');

const app = express();
const port = 3000;
const secretKey = 'your_secret_key';

app.use(express.json());
app.use(express.static('public'));

// SQLite adatbázis kapcsolódás
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Could not connect to database', err);
  } else {
    console.log('Connected to database');
  }
});

// Felhasználói tábla létrehozása
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `);
});

// Helper függvények
function generateToken(username) {
  return jwt.sign({ username }, secretKey, { expiresIn: '1h' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log(token);
  
  if (token == null) return res.sendStatus(403);

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Multer konfiguráció
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const folderPath = path.join(__dirname, 'uploads', req.body.path || '');
        fs.mkdirSync(folderPath, { recursive: true }); // A mappa létrehozása, ha nem létezik
        cb(null, folderPath);
    },
    filename: function (req, file, cb) {
        const ext = path.extname(file.originalname);
        const basename = path.basename(file.originalname, ext);
        const date = new Date().toISOString().replace(/:/g, '-');
        cb(null, `${basename}-${date}${ext}`); // Példa: file-2024-08-10T12-30-00.000Z.jpg
    }
});
// Felhasználó regisztráció
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [username, hashedPassword], (err) => {
    if (err) {
      return res.status(400).send('User already exists');
    }
    res.status(201).send('User registered');
  });
});

// Felhasználó bejelentkezés
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err || !user) {
      return res.status(401).send('Invalid credentials');
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (isValid) {
      const token = generateToken(user.username);
      res.json({ token });
    } else {
      res.status(401).send('Invalid credentials');
    }
  });
});

const upload = multer({ storage: storage }).array('file', 10); // Több fájl kezelése
const uploadsDir = path.join(__dirname, 'uploads');

app.get('/files/*', (req, res) => {
    const relativePath = req.params[0] || '';
    const directoryPath = path.join(uploadsDir, relativePath);

    fs.stat(directoryPath, (err, stats) => {
        if (err) {
            console.error(`Unable to access path: ${directoryPath}`, err);
            return res.status(500).send('Unable to retrieve files');
        }

        if (stats.isDirectory()) {
            fs.readdir(directoryPath, { withFileTypes: true }, (err, files) => {
                if (err) {
                    console.error(`Unable to read directory: ${directoryPath}`, err);
                    return res.status(500).send('Unable to retrieve files');
                }

                const fileInfos = files.map(file => {
                    const filePath = path.join(directoryPath, file.name);
                    const fileType = file.isDirectory() ? 'folder' : mime.lookup(filePath) || 'file';

                    return {
                        name: file.name,
                        type: fileType
                    };
                });

                res.json(fileInfos);
            });
        } else if (stats.isFile()) {
            res.sendFile(directoryPath);
        } else {
            res.status(400).send('Invalid path');
        }
    });
});

app.post('/create-folder', authenticateToken, (req, res) => {
    const { currentPath, folderName } = req.body;

    if (!folderName || folderName.trim() === '') {
        return res.status(400).send('Folder name is required.');
    }

    const folderPath = path.join(uploadsDir, currentPath, folderName);

    fs.mkdir(folderPath, { recursive: true }, (err) => {
        if (err) {
            return res.status(500).send('Error creating folder.');
        }
        res.status(201).send('Folder created successfully.');
    });
});
  
app.post('/upload', upload, (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).send('No files were uploaded.');
    }
    res.status(200).send('Files uploaded successfully.');
});

// Szerver indítása
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});