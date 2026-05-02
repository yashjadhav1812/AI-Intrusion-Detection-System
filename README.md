# AI-Intrusion-Detection-System

## 📌 Overview
The AI Intrusion Detection System is a cybersecurity-focused application designed to detect and classify malicious network activities using machine learning techniques.

This system analyzes real-time or recorded network traffic data and identifies potential cyber threats such as unauthorized access, abnormal traffic behavior, and attack patterns. The goal is to improve network security by providing intelligent and automated threat detection with high accuracy and reduced false positives.

---

## ⚙️ How It Works
The system follows a structured pipeline:

1. **Data Collection**
   - Network traffic dataset (e.g., DDoS, DNS attacks)

2. **Data Preprocessing**
   - Cleaning and formatting data
   - Feature selection and normalization

3. **Model Training**
   - Machine Learning algorithms are trained using labeled data
   - The trained model is saved (`ids_model.pkl`)

4. **Intrusion Detection**
   - Real-time or input data is passed to the model
   - The system predicts whether the activity is:
     - Normal
     - Malicious

5. **Monitoring Interface**
   - Web interface (HTML) displays detection results

---

## 🚀 How to Run the Project

### Step 1: Clone the repository
git clone https://github.com/yashjadhav1812/AI-Intrusion-Detection-System.git
cd Desktop/ai_ids_project

### Step 2: Install dependencies        
pip install -r requirements.txt
(If requirements.txt is not available, install manually:)                          
pip install pandas numpy scikit-learn flask

### Step 3: Start packet sniffer (for real-time detection)
sudo python3 sniffer.py

### Step 4: Train the model (optional)
python3 train_model.py

### Step 5: Run the application
python3 app.py

### Step 6: Open in browser
Go to:
http://127.0.0.1:5000/

## ⚠️Project Folder Structure
```
📁 ai_ids_project/
│
├── 📁 Database/              # Dataset folder
│   └── DrDos_DNS.csv        # Network traffic dataset used for training
│
├── 📁 templates/            # HTML files (Flask frontend)
│   ├── index.html           # Home page
│   └── monitor.html         # Live monitoring page
│
├── 📁 model/                 # Trained ML model
│   └── ids_model.pkl        # Saved intrusion detection model
│
├── app.py                   # Main Flask application (UI + backend logic)
├── sniffer.py               # Network packet capturing script
├── train_model.py           # Model training script
