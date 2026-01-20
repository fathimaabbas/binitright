# ♻️ Bin It Right

**Bin It Right** is a web-based waste management and environmental awareness platform designed to promote proper waste disposal, recycling, and eco-conscious behavior. The project combines **user participation**, **official/admin monitoring**, **image-based waste handling**, and **gamified learning** into a single system.

This project is suitable for **college submissions**, **hackathons**, and **portfolio demonstrations**.

---

## 🌍 Problem Statement

Improper waste segregation and lack of awareness about recycling lead to environmental damage and inefficient waste management systems. Bin It Right addresses this by:

* Encouraging users to recycle and sell waste responsibly
* Providing visual proof through image uploads
* Educating users using interactive eco-games and quizzes
* Allowing officials/admins to monitor submissions

---

## ✨ Features

### 👤 User Features

* User Registration & Login
* Submit recyclable waste details
* Upload images of recyclable items
* Submit reports regarding dumping wastes
* View reports submitted by the users
* Take immediate action in removing waste in public places
* View eco-awareness pages
* Participate in games and quizzes

### 🏛️ Official / Admin Features

* Secure official dashboard
* View submitted recyclable listings
* View uploaded images from users
* Delete collected / verified entries

### 🧠 Awareness & Gamification

* Eco Fun Zone
* Recycling awareness pages
* Quiz Game
* Memory Game
* Bin Game

---

## 🛠️ Tech Stack

| Layer          | Technology                       |
| -------------- | -------------------------------- |
| Frontend       | HTML, CSS (Segoe UI)             |
| Backend        | Node.js, Express.js              |
| Database       | MongoDB / MySQL (based on setup) |
| File Uploads   | Multer                           |
| Authentication | Sessions / Cookies               |
| Styling        | Custom CSS                       |

---

## 📁 Project Folder Structure

```
view/
│
├── official/
│   └── dashboard.html        # Admin dashboard
│
├── uploads/                  # User uploaded images
│   ├── 1768832274707.webp
│   ├── 1768832379108.webp
│   ├── 1768916942841.png
│   └── 1768918561202.jpg
│
├── binGame.html               # Waste sorting game
├── classify.html              # Waste classification page
├── eco-funzone.html           # Eco fun activities
├── feed.html                  # User feed / awareness
├── funzone.html               # Games hub
├── index.html                 # Landing page
├── login.html                 # Login page
├── memoryGame.html            # Memory game
├── payment.html               # Payment page
├── quizGame.html              # Quiz game
├── recycling.html             # Sell recyclables page
├── register.html              # Registration page
├── report.html                # Report / complaint page
│
├── style.css                  # Global styles
│
.env                           # Environment variables
```

---

## 🔄 Workflow

1. User registers and logs in
2. User submits recyclable waste details
3. Image is uploaded and stored in `view/uploads`
4. Data is stored in the database
5. Official logs into dashboard
6. Official views details and uploaded images
7. Official deletes or verifies collected data

---

## 🔐 Security Considerations

* Session-based authentication
* Image upload validation
* Protected admin routes
* Duplicate submission checks

---

## 🚀 Installation & Setup

```bash
# Clone repository
git clone <repository-url>

# Install dependencies
npm install

# Run server
node app.js
```

Create a `.env` file for configuration:

```
PORT=3000
DB_URL=your_database_url
SESSION_SECRET=your_secret_key
```

---

## 📌 Future Enhancements

* AI-based waste image classification
* Role-based access control
* Reward points for recycling
* Mobile-responsive PWA
* Deployment on cloud (Render / Railway)

---

## Hackathon Project 
## Team : HackHive
---

## 📄 License

This project is developed for educational and academic purposes.
