// server.js
// deps: npm i express mongoose dotenv cors cookie-parser bcryptjs jsonwebtoken multer cloudinary

import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";

/* ===================== Basic env checks ===================== */
const PORT = process.env.PORT || 4000;
const MONGO_URI = (process.env.DATABASE_URL || "").trim();
const JWT_SECRET = (process.env.JWT_SECRET || "").trim();

if (!MONGO_URI) {
  console.error("❌ Missing DATABASE_URL in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ Missing JWT_SECRET in .env");
  process.exit(1);
}

/* ===================== Express ===================== */
const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" })); // <— added
app.use(cookieParser());
app.use(
  cors({
    origin: ["http://localhost:3000"],
    credentials: true,
  })
);

/* ---------- Health check ---------- */
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

/* ===================== Mongoose models ===================== */
const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
  },
  { collection: "user_data", timestamps: true }
);
const User = mongoose.models.User || mongoose.model("User", UserSchema);

const PropertySchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true },
    description: { type: String, default: "" },
    price: { type: Number, default: 0 },
    capitalValue: { type: Number, default: 0 },
    bathrooms: { type: Number, default: 0 },
    rooms: { type: Number, default: 0 },
    parking: { type: Number, default: 0 },
    address: {
      line1: String,
      city: String,
      country: String,
    },
    location: {
      lat: Number,
      lng: Number,
      formatted: String,
    },
    images: [
      {
        url: { type: String, required: true },
        publicId: { type: String, required: true },
      },
    ],
    owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  },
  { collection: "properties", timestamps: true }
);
const Property = mongoose.models.Property || mongoose.model("Property", PropertySchema);

const BookingSchema = new mongoose.Schema(
  {
    property: { type: mongoose.Schema.Types.ObjectId, ref: "Property", required: true, index: true },
    guest: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    start: { type: Date, required: true, index: true },
    end: { type: Date, required: true, index: true },
    status: { type: String, enum: ["confirmed", "cancelled"], default: "confirmed" },
  },
  { collection: "bookings", timestamps: true }
);
BookingSchema.index({ property: 1, start: 1, end: 1 });
const Booking = mongoose.models.Booking || mongoose.model("Booking", BookingSchema);

/* ===================== Mongo connect ===================== */
async function initDb() {
  await mongoose.connect(MONGO_URI);
  console.log("✅ MongoDB connected");
  await mongoose.connection.db.collection("user_data").createIndex({ email: 1 }, { unique: true });
  await mongoose.connection.db.collection("properties").createIndex({ owner: 1, createdAt: -1 });
  await mongoose.connection.db.collection("bookings").createIndex({ property: 1, start: 1, end: 1 });
}

/* ===================== Cloudinary config ===================== */
function parseCloudinaryURL(url) {
  const m = /^cloudinary:\/\/([^:]+):([^@]+)@([^/]+)$/.exec(url || "");
  if (!m) return null;
  return { api_key: m[1], api_secret: m[2], cloud_name: m[3] };
}
const CLD_URL = (process.env.CLOUDINARY_URL || "").trim();
const CLD_NAME = (process.env.CLOUDINARY_CLOUD_NAME || "").trim();
const CLD_KEY = (process.env.CLOUDINARY_API_KEY || "").trim();
const CLD_SEC = (process.env.CLOUDINARY_API_SECRET || "").trim();

let cfg = null;
if (CLD_URL) {
  const parsed = parseCloudinaryURL(CLD_URL);
  cfg = { ...parsed, secure: true };
} else if (CLD_NAME && CLD_KEY && CLD_SEC) {
  cfg = { cloud_name: CLD_NAME, api_key: CLD_KEY, api_secret: CLD_SEC, secure: true };
} else {
  console.error("❌ Cloudinary not configured");
  process.exit(1);
}
cloudinary.config(cfg);

/* ===================== Auth helpers ===================== */
function signToken(user) {
  return jwt.sign({ _id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
}
function authGuard(req, res, next) {
  const token =
    req.cookies?.token ||
    (req.headers.authorization?.startsWith("Bearer ")
      ? req.headers.authorization.split(" ")[1]
      : null);
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

/* ===================== Auth routes ===================== */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: "All fields required" });
    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ error: "Email already in use" });
    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash });
    const token = signToken(user);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ message: "Signed up", user: { _id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    console.error("Signup error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });
    const token = signToken(user);
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 7 * 24 * 60 * 60 * 1000 });
    res.json({ message: "Logged in", user: { _id: user._id, name: user.name, email: user.email } });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie("token").json({ message: "Logged out" });
});

app.get("/api/me", authGuard, async (req, res) => {
  const me = await User.findById(req.user._id).select("_id name email createdAt");
  res.json({ user: me });
});

/* ---------- Protected probe for UI ---------- */
app.get("/api/secure/data", authGuard, (_req, res) => {
  res.json({ ok: true, note: "You are authenticated." });
});

/* ===================== Property routes ===================== */
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

/**
 * GET /api/properties
 * Query:
 *  - q: search text
 *  - page: 1-based page index (default 1)
 *  - limit: page size (default 12, max 50)
 *  - owner=me: filter by current user (requires auth)
 */
app.get("/api/properties", async (req, res) => {
  try {
    const { q = "", page = "1", limit = "12", owner } = req.query;

    const pageNum = Math.max(parseInt(page, 10) || 1, 1);
    const limitNum = Math.min(Math.max(parseInt(limit, 10) || 12, 1), 50);
    const skip = (pageNum - 1) * limitNum;

    const filter = {};

    if (q && String(q).trim()) {
      const rx = new RegExp(String(q).trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [
        { title: rx },
        { description: rx },
        { "address.line1": rx },
        { "address.city": rx },
        { "address.country": rx },
      ];
    }

    if (owner === "me") {
      try {
        const token =
          req.cookies?.token ||
          (req.headers.authorization?.startsWith("Bearer ")
            ? req.headers.authorization.split(" ")[1]
            : null);
        if (!token) return res.status(401).json({ error: "Unauthorized" });
        const payload = jwt.verify(token, JWT_SECRET);
        filter.owner = payload._id;
      } catch {
        return res.status(401).json({ error: "Unauthorized" });
      }
    }

    const [items, total] = await Promise.all([
      Property.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .select("title price address images location createdAt")
        .lean(),
      Property.countDocuments(filter),
    ]);

    res.json({
      items,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        hasMore: skip + items.length < total,
      },
    });
  } catch (e) {
    console.error("List properties error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/properties", authGuard, upload.array("images", 10), async (req, res) => {
  try {
    const {
      title,
      description,
      price,
      capitalValue,
      bathrooms,
      rooms,
      parking,
      line1,
      city,
      country,
      lat,
      lng,
    } = req.body || {};
    if (!title) return res.status(400).json({ error: "Title is required" });

    const uploaded = [];
    for (const f of req.files || []) {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: `realestate/${req.user._id}`, resource_type: "image" },
          (err, data) => (err ? reject(err) : resolve(data))
        );
        stream.end(f.buffer);
      });
      uploaded.push({ url: result.secure_url, publicId: result.public_id });
    }

    const doc = await Property.create({
      title,
      description,
      price: price ? Number(price) : 0,
      capitalValue: capitalValue ? Number(capitalValue) : 0,
      bathrooms: bathrooms ? Number(bathrooms) : 0,
      rooms: rooms ? Number(rooms) : 0,
      parking: parking ? Number(parking) : 0,
      address: { line1, city, country },
      location: { lat: lat ? Number(lat) : undefined, lng: lng ? Number(lng) : undefined },
      images: uploaded,
      owner: req.user._id,
    });

    res.status(201).json({ property: doc });
  } catch (err) {
    console.error("Create property error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/properties/:id", async (req, res) => {
  const item = await Property.findById(req.params.id)
    .populate("owner", "_id name email")
    .lean();
  if (!item) return res.status(404).json({ error: "Not found" });
  res.json({ property: item });
});

/* ===== UPDATE property (robust coercion & fresh return) ===== */
app.put("/api/properties/:id", authGuard, upload.array("images", 10), async (req, res) => {
  try {
    const { id } = req.params;
    const prop = await Property.findById(id);
    if (!prop) return res.status(404).json({ error: "Property not found" });

    if (String(prop.owner) !== String(req.user._id)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const b = req.body || {};
    const getNum = (x) => (x === "" || x == null ? undefined : Number(x));
    const getStr = (x) => (x == null ? undefined : String(x));

    // Normalize removePublicIds
    let toRemoveIds = [];
    const { removePublicIds } = b;
    if (Array.isArray(removePublicIds)) {
      toRemoveIds = removePublicIds;
    } else if (typeof removePublicIds === "string" && removePublicIds.trim()) {
      try {
        const parsed = JSON.parse(removePublicIds);
        if (Array.isArray(parsed)) toRemoveIds = parsed;
      } catch {}
    }

    // Remove selected images (and destroy in Cloudinary)
    if (toRemoveIds.length) {
      const toRemove = new Set(toRemoveIds.map(String));
      const keep = [];
      for (const img of prop.images || []) {
        if (toRemove.has(String(img.publicId))) {
          try { await cloudinary.uploader.destroy(img.publicId); } catch {}
        } else {
          keep.push(img);
        }
      }
      prop.images = keep;
    }

    // Upload new images
    for (const f of (req.files || [])) {
      const uploaded = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: `realestate/${req.user._id}`, resource_type: "image" },
          (err, data) => (err ? reject(err) : resolve(data))
        );
        stream.end(f.buffer);
      });
      prop.images.push({ url: uploaded.secure_url, publicId: uploaded.public_id });
    }

    // Scalars
    const title = getStr(b.title);
    const description = getStr(b.description);
    const price = getNum(b.price);
    const capitalValue = getNum(b.capitalValue);
    const bathrooms = getNum(b.bathrooms);
    const rooms = getNum(b.rooms);
    const parking = getNum(b.parking);

    if (title !== undefined) prop.title = title.trim();
    if (description !== undefined) prop.description = description; // allow ""
    if (price !== undefined) prop.price = isNaN(price) ? prop.price : price;
    if (capitalValue !== undefined) prop.capitalValue = isNaN(capitalValue) ? prop.capitalValue : capitalValue;
    if (bathrooms !== undefined) prop.bathrooms = isNaN(bathrooms) ? prop.bathrooms : bathrooms;
    if (rooms !== undefined) prop.rooms = isNaN(rooms) ? prop.rooms : rooms;
    if (parking !== undefined) prop.parking = isNaN(parking) ? prop.parking : parking;

    // Address
    const line1 = getStr(b.line1);
    const city = getStr(b.city);
    const country = getStr(b.country);
    if (line1 !== undefined || city !== undefined || country !== undefined) {
      prop.address = {
        line1: line1 !== undefined ? line1 : prop.address?.line1,
        city: city !== undefined ? city : prop.address?.city,
        country: country !== undefined ? country : prop.address?.country,
      };
    }

    // Location
    const lat = getNum(b.lat);
    const lng = getNum(b.lng);
    if (lat !== undefined || lng !== undefined) {
      prop.location = {
        lat: lat !== undefined && !isNaN(lat) ? lat : prop.location?.lat,
        lng: lng !== undefined && !isNaN(lng) ? lng : prop.location?.lng,
        formatted: prop.location?.formatted,
      };
    }

    await prop.save();

    // Return freshly-hydrated doc to avoid serialization oddities
    const fresh = await Property.findById(id).populate("owner", "_id name email").lean();
    res.json({ property: fresh });
  } catch (e) {
    console.error("Update property error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===== DELETE property ===== */
app.delete("/api/properties/:id", authGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const prop = await Property.findById(id);
    if (!prop) return res.status(404).json({ error: "Property not found" });

    if (String(prop.owner) !== String(req.user._id)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    // Clean up bookings
    await Booking.deleteMany({ property: id });

    // Delete images from Cloudinary
    for (const img of prop.images || []) {
      try { await cloudinary.uploader.destroy(img.publicId); } catch {}
    }

    await prop.deleteOne();
    res.json({ message: "Deleted" });
  } catch (e) {
    console.error("Delete property error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===================== Booking routes ===================== */
app.get("/api/properties/:id/bookings", async (req, res) => {
  try {
    const { id } = req.params;
    const { date } = req.query;
    const q = { property: id, status: "confirmed" };
    if (date) {
      const startDay = new Date(date + "T00:00:00.000Z");
      const endDay = new Date(date + "T23:59:59.999Z");
      q.start = { $lt: endDay };
      q.end = { $gt: startDay };
    }
    const items = await Booking.find(q).sort({ start: 1 }).lean();
    res.json({ bookings: items });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/properties/:id/bookings", authGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { startISO, endISO } = req.body || {};
    const start = new Date(startISO);
    const end = new Date(endISO);
    const now = new Date();

    if (!startISO || !endISO) return res.status(400).json({ error: "startISO and endISO required" });
    if (isNaN(start) || isNaN(end)) return res.status(400).json({ error: "Invalid datetime" });
    if (end <= start) return res.status(400).json({ error: "End must be after start" });
    if (start < now) return res.status(400).json({ error: "Cannot book in the past" });

    const property = await Property.findById(id);
    if (!property) return res.status(404).json({ error: "Property not found" });
    if (String(property.owner) === String(req.user._id)) {
      return res.status(400).json({ error: "You cannot book your own property" });
    }

    const conflict = await Booking.findOne({
      property: id,
      start: { $lt: end },
      end: { $gt: start },
      status: "confirmed",
    });
    if (conflict) return res.status(409).json({ error: "Timeslot already booked" });

    const created = await Booking.create({ property: id, guest: req.user._id, start, end, status: "confirmed" });
    res.status(201).json({ booking: created });
  } catch (e) {
    console.error("Create booking error:", e);
    res.status(500).json({ error: "Server error" });
  }
});

/* ===================== Start ===================== */
initDb()
  .then(() => app.listen(PORT, () => console.log(`🚀 Backend on http://localhost:${PORT}`)))
  .catch((err) => {
    console.error("DB init error:", err.message);
    process.exit(1);
  });
