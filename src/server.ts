import express, { Express, Request, Response } from "express";
import cors from 'cors';
import prisma from './prisma/prismaClient';  // Use the Prisma client
import authRoutes from './routes/authRoutes';
import protectedRoutes from './routes/protectedRoutes';
import redis from './redisClient';


const app: Express = express();
const PORT = 4000;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);

app.get("/", (req: Request, res: Response) => {
  res.send("Express + TypeScript Server");
});

app.get('/api', (req, res) => {
  res.send('API is running');
});

// Test the Prisma connection and start the server
async function main() {
  try {
    await prisma.$connect();  // Connecting to the database
    console.log('Connection to the database has been established successfully.');

    // Start the server
    app.listen(PORT, () => {
      console.log(`Server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Unable to connect to the database:', err);
  }
}

main()
  .catch(err => console.error('Error:', err))
  .finally(async () => {
    await prisma.$disconnect();  // Disconnect Prisma when done
  });
