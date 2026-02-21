@echo off
echo ==========================================
echo   🌱 PLANT DOCTOR - AUTO SETUP SCRIPT
echo ==========================================
echo.

REM -------------------------------
REM Step 1: Upgrade pip
REM -------------------------------
echo 🔄 Upgrading pip...
python -m pip install --upgrade pip

REM -------------------------------
REM Step 2: Install Python packages
REM -------------------------------
echo 📦 Installing required Python packages...

pip install tensorflow
pip install numpy
pip install flask
pip install flask-mysqldb
pip install bcrypt
pip install pillow
pip install werkzeug

echo.
echo ✅ Python packages installed successfully!
echo.

REM -------------------------------
REM Step 3: Create MySQL Database
REM -------------------------------
set /p MYSQL_PWD=🔐 Enter MySQL root password: 

echo.
echo 🛢️ Creating database and tables...

mysql -u root -p%MYSQL_PWD% <<EOF
CREATE DATABASE IF NOT EXISTS plant_doctor;
USE plant_doctor;

-- =========================
-- USERS TABLE
-- =========================
CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
);

-- =========================
-- SCAN HISTORY TABLE
-- =========================
CREATE TABLE IF NOT EXISTS scan_history (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    disease VARCHAR(100) NOT NULL,
    confidence FLOAT NOT NULL,
    image_path VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

EOF

echo.
echo 🎉 DATABASE SETUP COMPLETE!
echo ==========================================
echo ✅ Database: plant_doctor
echo ✅ Tables: users, scan_history
echo ==========================================
pause
