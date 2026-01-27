# ♻️ Bin It Right

**Bin It Right** is an AI-powered web-based waste management and environmental awareness platform that promotes proper waste segregation, recycling, and eco-conscious behavior.

The system integrates **image-based waste classification**, **user participation**, **official/admin monitoring**, and **gamified learning** into a single scalable platform.

This project is suitable for **college submissions**, **hackathons**, and **portfolio demonstrations**.

---

## 🌍 Problem Statement

Improper waste segregation and lack of awareness about recyclable materials lead to environmental pollution and inefficient waste management systems.

**Bin It Right** addresses this problem by:
- Encouraging responsible waste disposal and recycling
- Using **AI image classification** to identify waste type
- Collecting visual proof through image uploads
- Educating users via interactive games and quizzes
- Enabling officials/admins to monitor and verify submissions

---

## ✨ Features

### 👤 User Features
- User Registration & Login
- Camera-based waste image capture
- **AI-based waste classification (Organic / Recyclable)**
- Submit recyclable waste listings
- Upload image proof
- Report illegal waste dumping
- Access eco-awareness content
- Play educational games and quizzes

### 🏛️ Official / Admin Features
- Secure official dashboard
- View recyclable waste submissions
- View uploaded images
- Accept and mark waste as collected
- Delete verified records

### 🧠 AI & Intelligence
- CNN-based image classification
- Real-time prediction using trained model
- Python-based inference pipeline
- Backend-integrated AI API

### 🎮 Awareness & Gamification
- Eco Fun Zone
- Recycling awareness pages
- Quiz Game
- Memory Game
- Bin Sorting Game

---

## 🧠 AI Waste Classification

### 🔍 Supported Classes
- **Organic Waste**
- **Recyclable Waste**

### 📸 Input
- Camera-captured images from browser
- Uploaded waste images

### 📊 Output
- Predicted waste category
- Confidence score (percentage)

---

## 🧪 Model Training Process

### 📂 Dataset
The model is trained using an image dataset containing two classes:


### 🔄 Preprocessing
- Images resized to **128 × 128**
- Pixel values normalized (0–1)
- Train / validation split applied

### 🧠 Model Architecture
- Convolutional Neural Network (CNN)
- Conv2D + MaxPooling layers
- Dense fully connected layers
- Sigmoid activation for binary classification

### 💾 Model Output
- Trained model saved as `waste_model.h5`

---

## 🔮 Real-Time Prediction Workflow

1. User captures image using camera
2. Image is sent to backend using `fetch()`
3. Node.js stores image via Multer
4. Python script (`predict.py`) is executed
5. Trained model predicts waste type
6. Prediction result is returned as JSON
7. UI displays label and confidence

---

## 🛠️ Tech Stack

| Layer           | Technology                    |
|-----------------|-------------------------------|
| Frontend        | HTML, CSS (Segoe UI), JS      |
| Backend         | Node.js, Express.js           |
| AI / ML         | Python, TensorFlow, Keras     |
| Database        | PostgreSQL / MongoDB          |
| File Uploads    | Multer                        |
| Authentication  | JWT / Sessions                |

---

## 📁 Project Folder Structure

BINITRIGHT/
│
├── dataset/
│ └── Waste Classification Dataset/dataset/
│ ├── organic/
│ └── recyclable/
│
├── data/
│ ├── train/
│ └── val/
│
├── view/
│ ├── official/
│ ├── uploads/
│ ├── classify.html
│ ├── index.html
│ ├── recycling.html
│ ├── report.html
│ └── *.html
│
├── uploads/
│
├── train_model.py
├── predict.py
├── split_dataset.py
├── prepare_dataset.py
├── test_image.py
├── waste_model.h5
│
├── server.js
├── package.json
├── .gitignore
├── .env
└── README.md


---

## 🚀 Installation & Setup

### 1️⃣ Clone Repository
```bash
git clone <repository-url>
cd binitright
npm install
pip install tensorflow numpy pillow
node server.js
http://localhost:3000

## 🔐 Security Considerations
- JWT-based authentication
- Cookie-based session handling
- Secure login & protected routes
- Image upload validation
- Server-side AI inference isolation

📌 Future Enhancements

Multi-class waste classification

Reward points for recycling

Cloud deployment (Render / Railway)

Mobile-friendly PWA

Real-time analytics dashboard

🏆 Hackathon Project

Team Name: HackHive
Domain: AI for Sustainability

📄 License

This project is developed for educational and academic purposes only.