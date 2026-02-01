import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import authRoutes from './route/auth.route.js';
import env from './config/env.js';
import type { Request, Response } from 'express';


dotenv.config();

const app = express();


app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = Number(process.env.PORT ?? env.PORT ?? 5000);

app.get('/', (req: Request, res: Response) => {
  res.send('Hello, World!');
})


app.use('/api/auth', authRoutes); 

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
