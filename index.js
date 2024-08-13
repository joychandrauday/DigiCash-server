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
  origin: ["http://localhost:5173", "http://localhost:5174","https://digitalcash.web.app"],
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
    const transactionsCollection = client
      .db("DigiCash")
      .collection("transactions");

    // Verify Token Middleware
    const verifyToken = async (req, res, next) => {
      const token = req.cookies?.token;
      if (!token) {
        return res.status(401).json({ message: "unauthorized access" });
      }
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
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
      const isAdmin = user?.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access." });
      }
      next();
    };
    // Registration
    app.post("/users/register", async (req, res) => {
      const { name, pin, mobile, email, role, isAgent, image_url } = req.body;

      if (!name || !pin || !mobile || !email) {
        return res.status(400).json({ message: "All fields are required" });
      }
      const exist = await usersCollection.findOne({ mobile: mobile });
      if (exist) {
        return res
          .status(400)
          .json({ message: "the number is already in use." });
      }
      const existEmail = await usersCollection.findOne({ email: email });
      if (existEmail) {
        return res
          .status(400)
          .send({ message: "the Email is already in use." });
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
        image_url,
        balance: 0,
      };

      await usersCollection.insertOne(newUser);
      res
        .status(201)
        .json({ message: "User registered successfully", user: newUser });
    });

    // Admin approval
    app.patch("/users/:mobile", async (req, res) => {
      const mobile = req.params.mobile;
      const user = await usersCollection.findOne({ mobile: mobile });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updatedUser = await usersCollection.updateOne(
        { mobile },
        { $set: { role: "user", balance: 40 } }
      );

      res
        .status(200)
        .send({ message: "User approved successfully", user: updatedUser });
    });
    app.patch("/agent/:mobile", async (req, res) => {
      const mobile = req.params.mobile;
      const user = await usersCollection.findOne({
        mobile: mobile,
        isAgent: true,
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updatedUser = await usersCollection.updateOne(
        { isAgent: true, mobile: mobile },
        { $set: { role: "agent", balance: 10000 } }
      );

      res
        .status(200)
        .send({ message: "User approved successfully", user: updatedUser });
    });
    app.patch("/make-agent/:mobile", async (req, res) => {
      const mobile = req.params.mobile;
      const user = await usersCollection.findOne({
        mobile: mobile,
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updatedUser = await usersCollection.updateOne(
        { mobile: mobile },
        { $set: { role: "agent", balance: 10000 } }
      );

      res
        .status(200)
        .send({ message: "User approved successfully", user: updatedUser });
    });
    app.patch("/admin/:mobile", async (req, res) => {
      const mobile = req.params.mobile;
      const user = await usersCollection.findOne({
        mobile: mobile,
      });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const updatedUser = await usersCollection.updateOne(
        { mobile: mobile },
        { $set: { role: "admin" } }
      );

      res
        .status(200)
        .send({ message: "User approved successfully", user: updatedUser });
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
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
            path: "/", // Make sure the path matches where the cookie was set
          })
          .status(200)
          .send({ success: true });
      } catch (err) {
        res.status(500).send(err);
      }
    });

    app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
      const cursor = usersCollection.find();
      const result = await cursor.toArray();
      res.send(result);
    });
    app.get("/protected", verifyToken, (req, res) => {
      res.status(200).send({ message: "This is a protected route" });
    });
    app.get("/user", verifyToken, async (req, res) => {
      try {
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
    app.get("/user/:phone", verifyToken, async (req, res) => {
      try {
        const phone = req.params.phone;
        const user = await usersCollection.findOne({ mobile: phone });
        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }
        res.status(200).send(user);
      } catch (err) {
        console.error("Error fetching user data:", err);
        res.status(500).send({ message: "Server error" });
      }
    });
    app.get("/users/agent", verifyToken, async (req, res) => {
      try {
        const query = { role: "agent" };
        const result = await usersCollection.find(query).toArray();
        res.send(result);
      } catch (err) {
        console.error("Error fetching user data:", err);
        res.status(500).send({ message: "Server error" });
      }
    });
    app.delete("/user/:mobile", async (req, res) => {
      const mobile = req.params.mobile;
      const query = { mobile: mobile };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });
    //transactions
    app.get("/total-balance", verifyToken, verifyAdmin, async (req, res) => {
      try {
        // Aggregate to calculate the total balance
        const result = await usersCollection
          .aggregate([
            {
              $group: {
                _id: null,
                totalBalance: { $sum: "$balance" },
              },
            },
          ])
          .toArray();
        const totalBalance = result[0]?.totalBalance || 0;
        const formatter = new Intl.NumberFormat("en-BD", {
          style: "currency",
          currency: "BDT",
          minimumFractionDigits: 2,
          maximumFractionDigits: 2,
        });
        const formattedBalance = formatter.format(totalBalance);

        // Respond with the formatted total balance
        res.json({
          totalBalance: formattedBalance,
        });
      } catch (error) {
        console.error("Error calculating total balance:", error);
        res.status(500).json({ error: "Internal Server Error" });
      }
    });
    app.get("/transactions", verifyToken, async (req, res) => {
      const cursor = transactionsCollection.find();
      const result = await cursor.toArray();
      res.send(result);
    });
    app.get("/transactions/:mobile", verifyToken, async (req, res) => {
      try {
        const mobile = req.params.mobile;
        const transaction = await transactionsCollection
          .find({ mobile: mobile })
          .toArray();
        if (!transaction) {
          return res.status(404).send({ message: "transaction not found" });
        }
        res.status(200).send(transaction);
      } catch (err) {
        console.error("Error fetching user data:", err);
        res.status(500).send({ message: "Server error" });
      }
    });
    app.get("/transactions-agent/:mobile", verifyToken, async (req, res) => {
      try {
        const mobile = req.params.mobile;

        // Use the $or operator to match either recipient or mobile field
        const transaction = await transactionsCollection
          .find({
            $or: [{ recipient: mobile }, { mobile: mobile }],
            method: { $in: ["cashin", "cashout"] },
          })
          .toArray();

        if (!transaction || transaction.length === 0) {
          return res.status(404).send({ message: "Transaction not found" });
        }

        res.status(200).send(transaction);
      } catch (err) {
        console.error("Error fetching transaction data:", err);
        res.status(500).send({ message: "Server error" });
      }
    });

    app.post("/transactions", verifyToken, async (req, res) => {
      const { mobile, recipient, amount, totalAmount, pin, method } = req.body;
      const user = await usersCollection.findOne({
        $or: [{ mobile: mobile }],
      });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(pin, user.pin);

      if (!isMatch) {
        return res.status(400).json({ message: "Invalid PIN" });
      }

      /////////////////send  money/////////////////
      if (method === "send-money") {
        const digicashProfit = totalAmount - amount;
        const transaction = {
          mobile,
          amount,
          method,
          recipient,
          totalAmount,
          digicashProfit,
          timestamp: new Date(),
        };
        const session = await client.startSession();
        session.startTransaction();

        // Update the sender's balance
        await usersCollection.updateOne(
          { mobile: mobile },
          { $inc: { balance: -totalAmount } },
          { session }
        );

        // Update the recipient's balance
        await usersCollection.updateOne(
          { mobile: recipient },
          { $inc: { balance: amount } },
          { session }
        );

        // Insert the transaction
        await transactionsCollection.insertOne(transaction, { session });

        // Commit the transaction
        await session.commitTransaction();
        session.endSession();

        res.status(201).send({ message: "Your transaction is successful." });
      } else if (method === "cashout") {
        /////////////////Cash Out/////////////////
        const transaction = {
          mobile,
          amount,
          method,
          recipient,
          totalAmount,
          timestamp: new Date(),
        };

        const session = await client.startSession();
        session.startTransaction();

        // Update the sender's balance
        await usersCollection.updateOne(
          { mobile: mobile },
          { $inc: { balance: -totalAmount } },
          { session }
        );

        // Update the recipient's balance
        await usersCollection.updateOne(
          { mobile: recipient },
          { $inc: { balance: +totalAmount } },
          { session }
        );

        // Insert the transaction
        await transactionsCollection.insertOne(transaction, { session });

        // Commit the transaction
        await session.commitTransaction();
        session.endSession();

        res.status(201).send({ message: "Your transaction is successful." });
      } else if (method === "cashin") {
        /////////////////Cash In/////////////////
        const transaction = {
          mobile,
          amount,
          method,
          recipient,
          totalAmount,
          timestamp: new Date(),
        };
        const session = await client.startSession();
        session.startTransaction();

        // Update the sender's balance
        await usersCollection.updateOne(
          { mobile: mobile },
          { $inc: { balance: -totalAmount } },
          { session }
        );

        // Update the recipient's balance
        await usersCollection.updateOne(
          { mobile: recipient },
          { $inc: { balance: +totalAmount } },
          { session }
        );

        // Insert the transaction
        await transactionsCollection.insertOne(transaction, { session });

        // Commit the transaction
        await session.commitTransaction();
        session.endSession();

        res.status(201).send({ message: "Your transaction is successful." });
      }
    });
    app.post("/cashin-request", verifyToken, async (req, res) => {
      try {
        const { mobile, recipient, amount } = req.body;

        // Validate the amount
        if (amount < 50) {
          return res
            .status(400)
            .send({ message: "Transaction amount must be at least 50 Taka." });
        }

        // Create a cash-in request
        const cashinRequest = {
          mobile,
          recipient,
          amount,
          method: "cashin",
          status: "pending", // Set the initial status to pending
          timestamp: new Date(),
        };

        // Insert the request into the transactions collection
        await transactionsCollection.insertOne(cashinRequest);

        res
          .status(201)
          .send({ message: "Cash-in request created successfully." });
      } catch (err) {
        console.error("Error creating cash-in request:", err);
        res.status(500).send({ message: "Server error" });
      }
    });
    app.post("/approve-cashin", verifyToken, async (req, res) => {
      try {
        const { requestId, agentMobile } = req.body;

        // Find the cash-in request
        const cashinRequest = await transactionsCollection.findOne({
          _id: new ObjectId(requestId),
          status: "pending",
        });

        if (!cashinRequest) {
          return res.status(404).send({
            message: "Cash-in request not found or already approved.",
          });
        }

        // Check the agent's balance
        const agent = await usersCollection.findOne({ recipient: agentMobile });
        if (agent?.balance < cashinRequest.amount) {
          return res
            .status(400)
            .send({ message: "Agent does not have enough balance." });
        }

        // Update the balances
        await usersCollection.updateOne(
          { mobile: cashinRequest.mobile },
          { $inc: { balance: cashinRequest.amount } }
        );
        await usersCollection.updateOne(
          { mobile: agentMobile },
          { $inc: { balance: -cashinRequest.amount } }
        );

        // Update the cash-in request status
        await transactionsCollection.updateOne(
          { _id: new ObjectId(requestId) },
          { $set: { status: "approved", totalAmount: cashinRequest.amount } }
        );

        res
          .status(200)
          .send({ message: "Cash-in request approved successfully." });
      } catch (err) {
        console.error("Error approving cash-in request:", err);
        res.status(500).send({ message: "Server error" });
      }
    });
    // Decline Cash-In Request
    app.post("/decline-cashin", verifyToken, async (req, res) => {
      try {
        const { requestId } = req.body;

        // Find the cash-in request
        const cashinRequest = await transactionsCollection.findOne({
          _id: new ObjectId(requestId),
          status: "pending",
        });

        if (!cashinRequest) {
          return res
            .status(404)
            .send({
              message: "Cash-in request not found or already processed.",
            });
        }

        // Update the cash-in request status to declined
        await transactionsCollection.updateOne(
          { _id: new ObjectId(requestId) },
          { $set: { status: "declined" } }
        );

        res
          .status(200)
          .send({ message: "Cash-in request declined successfully." });
      } catch (err) {
        console.error("Error declining cash-in request:", err);
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
