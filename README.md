# 🏥 Pulse HMS DBMS
A Hospital Management System Database Management project designed to efficiently manage hospital operations including patients, doctors, appointments, and medical records.

---

## 📌 Overview
Pulse HMS DBM is a database-driven system that helps streamline hospital workflows by organizing and managing critical data such as patient information, doctor details, appointments, billing, and more.

This project focuses on **database design and management**, ensuring data consistency, integrity, and efficient querying.

---

## 🚀 Features
- 👨‍⚕️ Doctor Management (Add, Update, Delete, View)
- 🧑‍🤝‍🧑 Patient Records Management
- 📅 Appointment Scheduling System
- 💊 Medical History Tracking
- 💰 Billing & Payment Records
- 🔍 Efficient Data Retrieval using SQL Queries
- 🔐 Data Integrity using Constraints and Relationships

---

## 🛠️ Tech Stack
### 🔹 Database
- SQLite
### 🔹 Backend
- Python
- Flask Framework

### 🔹 Frontend
- HTML
- CSS

---

## 🗂️ Database Structure
The system is designed using relational database concepts:

### Main Tables:
- `Patients`
- `Doctors`
- `Appointments`
- `Medical_Records`
- `Billing`
- `Departments`

### Relationships:
- One-to-Many (Doctor → Patients)
- One-to-Many (Patient → Appointments)
- One-to-One (Patient → Medical Records)

---

## 📊 ER Diagram
*(coming soon)*


---

## ⚙️ Installation & Setup

### 1️⃣ Clone the repository
```bash
git clone https://github.com/smsmorsalin/pulse-HMS_DBMS.git
```
```bash
cd pulse-HMS_DBMS
```
### 2️⃣ Create virtual environment (optional but recommended)    # Windows
```bash
python -m venv venv
```
```bash
venv\Scripts\activate
```
### 3️⃣ Install dependencies
```bash
pip install -r requirements.txt
```
### 4️⃣ Run the application
```bash
python app.py
```

### 5️⃣ Open in browser
```bash
http://127.0.0.1:5000/
```
