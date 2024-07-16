const express = require("express");
const bcrypt = require("bcryptjs");
const app = express();
require("dotenv").config();
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");

const port = process.env.PORT || 8000;

// middleware
const corsOptions = {
  origin: ["http://localhost:5173", "http://localhost:5174"],
  credentials: true,
  optionSuccessStatus: 200,
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nsswhi9.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const usersCollection = client.db("DigiCash").collection("users");

    // Verify Token Middleware
    const verifyToken = async (req, res, next) => {
      const token = req.cookies?.token;
      if (!token) {
        return res.status(401).json({ message: "unauthorized access" });
      }
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          console.log(err);
          return res.status(401).json({ message: "unauthorized access" });
        }
        req.user = decoded;
        next();
      });
    };

    const verifyAdmin = async (req, res, next) => {
      const email = req.user.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      const isAdmin=user?.role === 'admin';
      if(!isAdmin){
        return res.status(403).send({message: 'forbidden access.'})
      }
      next();
    };
    // Registration
    app.post("/users/register", async (req, res) => {
      const { name, pin, mobile, email, role, isAgent } = req.body;

      if (!name || !pin || !mobile || !email) {
        return res.status(400).json({ message: "All fields are required" });
      }

      if (!/^\d{5}$/.test(pin)) {
        return res
          .status(400)
          .json({ message: "PIN must be a 5-digit number" });
      }

      const hashedPin = await bcrypt.hash(pin, 10);

      const newUser = {
        name,
        pin: hashedPin,
        mobile,
        email,
        role,
        isAgent,
        balance: 0,
      };

      await usersCollection.insertOne(newUser);
      res
        .status(201)
        .json({ message: "User registered successfully", user: newUser });
    });

    // Admin approval
    app.post("/users/approve", async (req, res) => {
      const { email } = req.body;
      const user = await usersCollection.findOne({ email });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updatedUser = await usersCollection.updateOne(
        { email },
        { $set: { status: "approved", balance: 40 } }
      );

      res
        .status(200)
        .json({ message: "User approved successfully", user: updatedUser });
    });

    // Login
    app.post("/users/login", async (req, res) => {
      const { identifier, pin } = req.body;
      const user = await usersCollection.findOne({
        $or: [{ mobile: identifier }, { email: identifier }],
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(pin, user.pin);

      if (!isMatch) {
        return res.status(400).json({ message: "Invalid PIN" });
      }

      const token = jwt.sign(
        { email: user.email },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "1h" }
      );
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ message: "Login successful", token });
    });

    // Auth related API
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "365d",
      });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
        })
        .send({ success: true });
    });

    // Logout
    app.get("/logout", async (req, res) => {
      try {
        res
          .clearCookie("token", {
            maxAge: 0,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
          })
          .send({ success: true });
        console.log("Logout successful");
      } catch (err) {
        res.status(500).send(err);
      }
    });
    app.get("/users", verifyToken,verifyAdmin, async (req, res) => {
      const cursor = usersCollection.find();
      const result = await cursor.toArray();
      res.send(result);
    });

    app.get("/protected", verifyToken, (req, res) => {
      res.status(200).send({ message: "This is a protected route" });
    });
    app.get("/user", verifyToken, async (req, res) => {
      try {
        console.log(req.user);
        const user = await usersCollection.findOne({ email: req.user.email });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        res.status(200).send(user);
      } catch (err) {
        console.error("Error fetching user data:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("DigiCash server is running...");
});

app.listen(port, () => {
  console.log(`DigiCash is running on port ${port}`);
});
