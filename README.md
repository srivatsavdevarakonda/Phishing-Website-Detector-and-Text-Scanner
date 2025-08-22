# 🛡️ Phishing Detector Pro

**Phishing Detector Pro** is a web-based tool built with **Flask** that detects phishing risks in URLs and text messages using **multi-layered heuristic analysis**. It’s designed for students, developers, and security enthusiasts to quickly evaluate digital threats with a clean, simple interface.

---

## 📌 Features

* 🌐 **URL Analysis:** Deep scan of URLs for common phishing indicators.
* ✉️ **Text/Message Analysis:** Detects suspicious keywords, spoofed senders, and hidden malicious links.
* ⚡ **Local Threat Intelligence:** Uses a lightweight, offline phishing database (`local_phishtank_db.json`) for fast checks without API limits.
* 📊 **Heuristic Risk Scoring:** Calculates a weighted **risk score (0-100)**, labeling results as **Likely Safe**, **Suspicious**, or **High Risk**.
* 🎨 **Clean & Responsive UI:** Modern frontend with HTML, CSS, and JavaScript.

---

## 🚀 Live Demo

> 🔗 **[https://phishing-website-detector-and-text.onrender.com](phishing-website-detector-and-text-scanner)**

---

## 🖼️ Screenshots 
**Homepage:**

<img width="804" height="393" alt="image" src="https://github.com/user-attachments/assets/9c36c63d-eb25-4d3c-a021-7716e49d3af9" />

**URL Analysis Result:**

<img width="841" height="809" alt="image" src="https://github.com/user-attachments/assets/2f238ee4-97fb-496b-9f48-00ca02b328e4" />

**Text Analysis Result:**

<img width="786" height="845" alt="image" src="https://github.com/user-attachments/assets/cff4b243-c95e-461f-bc68-bbcb11e7ba3d" />

---

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **Frontend:** HTML5, CSS3, JavaScript (Fetch API)
* **Libraries:** `requests`, `python-whois`, `pyOpenSSL`

---

## 📂 Directory Structure

```
phishing_detector_flask/
│
├── static/
│   ├── style.css
│   └── script.js
│
├── templates/
│   └── index.html
│
├── app.py
├── local_phishtank_db.json
├── requirements.txt
└── README.md
```

---

## 🖥️ Local Installation

To run this project locally:

1. **Clone the repository**

   ```bash
   git clone https://github.com/your-username/phishing_detector_flask.git
   cd phishing_detector_flask
   ```

2. **Set up a virtual environment**

   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # macOS/Linux
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**

   ```bash
   python app.py
   ```

   Visit **[http://127.0.0.1:5000](https://phishing-website-detector-and-text.onrender.com)** in your browser.

---

## 💡 How to Use

1. **URL Analysis**

   * Go to the **URL Analysis** tab.
   * Enter a website link.
   * Click **“Analyze URL”** → Get risk score & breakdown.

2. **Text/Message Analysis**

   * Go to **Text/Message Analysis**.
   * Paste the full text of an email/SMS.
   * Click **“Analyze Text”** → View risk score & suspicious link analysis.

---

## 👨‍💻 Author Info

**Developed by:** (SRIVATSAV D)
📧 [devarakondasrivatsav@gmail.com](mailto:devarakondasrivatsav@gmail.com)
🌐 [GitHub](https://github.com/srivatsavdevarakonda) | [LinkedIn]([https://www.linkedin.com/in/your-link](https://www.linkedin.com/in/d-srivatsav-2a7a90247/))

---

## 📝 License

This project is licensed under the **MIT License**.

---

## 🙌 Contributing

Contributions are welcome!

```bash
git fork
git clone [your forked repo]
git checkout -b feature-branch
# make changes & commit
git push origin feature-branch
```

Open a **Pull Request** and let’s collaborate 🚀

---

## 🔮 Future Improvements

* Add **ML-based phishing detection** for smarter risk prediction.
* Support **browser extension integration** for real-time detection.
* Add **user accounts** with history tracking.
* Implement **threat feed API integration** for live updates.

---

## 💬 A Final Note

> Stay safe online. Think before you click. 🕵️‍♂️

---

