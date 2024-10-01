const express = require('express');
const { OpenAI } = require("openai");
const { Pool } = require('pg');
const bcrypt = require("bcrypt")
const jwt = require('jsonwebtoken')
//require('dotenv').config();
const dotenv = require('dotenv');
if (process.env.NODE_ENV === 'local') {
    // 如果是 'local'，则加载 .local 文件
    dotenv.config({ path: './.local' });
  } else {
    // 否则，加载 .env 文件
    dotenv.config();
  }
const tf = require('@tensorflow/tfjs-node');

const app = express();
const port = process.env.PORT || 3002;
const cors = require('cors');
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

const pool = new Pool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});
console.log('!!',{
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
})
console.log(process.env.NODE_ENV)
const query = (text, params) => pool.query(text, params);
app.get('/health',(req,res)=>{
    res.send("我還活著")
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
  
    if (token == null) return res.sendStatus(401);
  
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  }
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
      message: "這是受保護的資料",
      user: req.user.username,
      someData: "這裡可以是任何您想返回的數據"
    });
  });
app.post('/api/register', async (req, res) => {
    console.log('Register route hit');
    console.log('Request body:', req.body);
    
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
  
    try {
      // Check if user already exists
      const userCheck = await query('SELECT * FROM users WHERE username = $1', [username]);
      if (userCheck.rows.length > 0) {
        return res.status(409).json({ error: 'Username already exists' });
      }
  
      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Insert new user
      const result = await query(
        'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id',
        [username, hashedPassword]
      );
  
      res.status(201).json({ message: 'User registered successfully', userId: result.rows[0].id });
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).json({ error: 'An error occurred during registration' });
    }
  });
  
  // Login endpoint
  app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
  
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }
  
    try {
      // Find user
      const result = await query('SELECT * FROM users WHERE username = $1', [username]);
      const user = result.rows[0];
  
      if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
  
      // Check password
      const isValidPassword = await bcrypt.compare(password, user.password);
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }
  
      // Generate JWT
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  
      res.json({ message: 'Login successful', token });
    } catch (err) {
      console.error('Login error:', err);
      res.status(500).json({ error: 'An error occurred during login' });
    }
  });
app.post('/api/add-question', async (req, res) => {
    const { message, response } = req.body;

    if (!message || !response) {
        return res.status(400).json({ error: 'Message and response are required' });
    }

    try {
        const embedding = await getEmbedding(message);
        if (embedding.length !== 1536) {
            throw new Error(`Expected 1536 dimensions, but got ${embedding.length}`);
        }

        // 将 embedding 数组转换为 JSON 字符串
        const embeddingString = JSON.stringify(embedding);

        await pool.query(`
            INSERT INTO chatbot (message, response, embedding)
            VALUES ($1, $2, $3);
        `, [message, response, embeddingString]);

        res.status(201).json({ message: 'Question successfully added to database' });
    } catch (err) {
        console.error('Error adding question to database:', err);
        res.status(500).json({ error: 'An error occurred while adding the question' });
    }
});

async function translateResponse(userQuery, response) {
    const completion = await openai.chat.completions.create({
        model: "gpt-4",  // 或其他適合的模型
        messages: [
            {
                role: "system",
                content: `You are a translator. Follow these steps:
                1. Identify the language of the user's query.
                2. Identify the language of the response to be translated.
                3. Translate the response into the language of the user's query.
                4. Do NOT translate any Markdown syntax, URLs, or text within backticks or square brackets.
                5. Preserve all formatting, including newlines, bold, italic, and list structures.
                6. If the user's query and the response are already in the same language, return the original response without translation.
                7. If the user's language is Chinese, use Traditional Chinese (zh-tw) for the translation, not Simplified Chinese.
                8. Ensure that the final output is in the same language as the user's query, regardless of the original response language.
                9. Output ONLY the translated or original text without any explanations, summaries, or metadata about the translation process.`
            },
            {
                role: "user",
                content: `User query: "${userQuery}"\n\nResponse to translate: ${response}`
            }
        ],
        temperature: 0.3,  // 低溫度以獲得更一致的翻譯
    });

    return completion.choices[0].message.content;
}

async function getEmbedding(text) {
    const response = await openai.embeddings.create({
        model: "text-embedding-ada-002",
        input: text,
    });
    const embedding = response.data[0].embedding;
    if (embedding.length !== 1536) {
        throw new Error(`Expected 1536 dimensions, but got ${embedding.length}`);
    }
    return embedding;
}
app.post('/api/chat', async (req, res) => {
    const { messages } = req.body;
    const queryMessage = messages[messages.length - 1].content;
    console.log('Received message:', queryMessage);
    try {
        const queryVector = await getEmbedding(queryMessage);
        
        if (queryVector.length !== 1536) {
            throw new Error(`Expected 1536 dimensions, but got ${queryVector.length}`);
        }

        const vectorString = `[${queryVector.join(',')}]`;
        console.log('Vector string:', vectorString);


        const result = await pool.query(`
            SELECT response, 1 - (embedding <-> $1::vector(1536)) AS similarity
            FROM chatbot
            ORDER BY similarity DESC
            LIMIT 1;
        `, [vectorString]);

        console.log('Query result:', result.rows);

        if (result.rows.length > 0 ) {  // 設置一個相似度閾值 && result.rows[0].similarity > 0.8
            const originalResponse = result.rows[0].response;
            const translatedResponse = await translateResponse(queryMessage, originalResponse);
            res.json({ response: translatedResponse });
        } else {
            res.json({ response: 'I do not have a relevant response for that message.' });
        }
    } catch (err) {
        console.error('Error processing request:', err);
        res.status(500).json({ error: err.message });
    }
});

app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
});

// 404 处理
app.use((req, res) => {
    console.log(`404 Not Found: ${req.method} ${req.url}`);
    res.status(404).json({ error: "Route not found" });
});
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});