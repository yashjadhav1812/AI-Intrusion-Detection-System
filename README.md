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
```bash
git clone https://github.com/yashjadhav1812/AI-Intrusion-Detection-System.git
cd AI-Intrusion-Detection-System
