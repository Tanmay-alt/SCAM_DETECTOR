# Scam Detector: AI-Powered Threat Intelligence Platform

Scam Detector is a comprehensive, full-stack web application designed to empower users to identify and understand digital threats. It leverages a custom-trained machine learning model, multiple third-party APIs, and advanced data analysis tools to provide real-time risk analysis for emails, websites, IP addresses, and SMS messages. The platform is built with a secure, scalable, and modern technology stack, fully containerized with Docker for consistent development and deployment.

Login Screen: ![Screenshot 2025-06-28 at 10 10 35 PM](https://github.com/user-attachments/assets/c2bc3959-f301-4eb0-9b24-6cbc9688a66f)
Homepage: ![Screenshot 2025-06-28 at 10 10 24 PM](https://github.com/user-attachments/assets/43063cd9-feb5-4a61-8c6d-5244338d17ab)
Threat Intelligence Dashboard: ![Screenshot 2025-06-28 at 10 11 30 PM](https://github.com/user-attachments/assets/fb8ff570-4b78-425b-8252-b066ccfd3fb0)
AI Phishing Simulator: ![Screenshot 2025-06-28 at 10 11 43 PM](https://github.com/user-attachments/assets/2b43ed9a-b57a-41c2-bb68-79480143af5b)
PII Data Scrubber: ![Screenshot 2025-06-28 at 10 11 53 PM](https://github.com/user-attachments/assets/6074d634-51d2-4e01-85af-0d1304033640)




## Core Features

* **Multi-Vector Analysis:** A unified interface to analyze four key threat vectors:
    * **Email Analysis:** Scans email content and headers using a custom `scikit-learn` model to detect phishing language, urgency tactics, and other malicious patterns.
    * **Website Analysis:** Checks any URL against known phishing databases, calculates domain age via WHOIS lookups, and integrates VirusTotal for a comprehensive risk score.
    * **IP Reputation:** Queries real-time DNS blocklists (like Spamhaus) and provides geolocation data for any IP address.
    * **SMS/Text Message Analysis:** A dedicated tool to analyze suspicious text messages. It assesses the message text with the ML model and analyzes the sender's phone number using the Twilio API to check for suspicious line types (e.g., VoIP).

* **User & Data Management:**
    * **Secure User Accounts:** Full registration and login functionality with hashed passwords.
    * **Persistent History:** All user analyses are saved to a secure PostgreSQL database, creating a personal threat history.
    * **Export to CSV:** Users can export their entire analysis history to a CSV file.

* **Advanced Tools Suite:**
    * **Intelligence Dashboard:** A private dashboard for each user that visualizes their personal analysis data, showing risk trends and top threats.
    * **AI Phishing Simulator:** Uses the Google Gemini Generative AI API to create realistic, educational phishing emails based on user-provided scenarios. These simulated emails are then sent to the user via the SendGrid API.
    * **PII Data Scrubber:** An advanced tool that allows users to upload a CSV file, specify columns, and have the application automatically find and mask Personally Identifiable Information (PII) like names, locations, and organizations using the `spaCy` NLP library.

## Technology Stack

This project was built using a modern, scalable technology stack to demonstrate a wide range of professional development skills.

* **Backend:** Python, Flask
* **Database:** PostgreSQL (Production), SQLite (Development), SQLAlchemy (ORM), Flask-Migrate
* **Frontend:** HTML5, CSS3, JavaScript, Bootstrap 5, Chart.js
* **Machine Learning / AI:**
    * **Predictive ML:** Scikit-learn, Pandas, NumPy
    * **NLP:** spaCy, pyap (for address parsing)
    * **Generative AI:** Google Gemini API
* **DevOps & Deployment:**
    * **Containerization:** Docker, Docker Compose
    * **WSGI Server:** Gunicorn
    * **Cloud Hosting:** Deployed on both PaaS (Render) and IaaS (AWS EC2) environments.
* **Third-Party APIs:**
    * **Email Delivery:** SendGrid
    * **Phone Intelligence:** Twilio Lookup API
    * **Threat Intelligence:** VirusTotal API, OpenPhish, Cisco Umbrella

## How to Run Locally

This project is fully containerized with Docker and is the recommended way to run it.

### Prerequisites
* Docker & Docker Compose
* Git

### Setup Instructions

1.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Tanmay-alt/SCAM_DETECTOR.git](https://github.com/Tanmay-alt/SCAM_DETECTOR.git)
    cd SCAM_DETECTOR
    ```

2.  **Create the Environment File:**
    Create a new file named `.env` in the project root. This file holds all the necessary API keys. Copy the content below and paste in your own keys.
    ```
    FLASK_APP=app.py
    FLASK_ENV=development
    DATABASE_URL=sqlite:////app/database.db
    SECRET_KEY=a-super-secret-key-for-local-dev
    CACHE_TYPE=simple
    VIRUSTOTAL_API_KEY=YOUR_VIRUSTOTAL_KEY
    GEMINI_API_KEY=YOUR_GEMINI_API_KEY
    SENDGRID_API_KEY=YOUR_SENDGRID_API_KEY
    MAIL_FROM_EMAIL=YOUR_VERIFIED_SENDER_EMAIL
    TWILIO_ACCOUNT_SID=YOUR_TWILIO_ACCOUNT_SID
    TWILIO_AUTH_TOKEN=YOUR_TWILIO_AUTH_TOKEN
    ```

3.  **(For Mac/Linux users) Make Startup Script Executable:**
    ```bash
    chmod +x boot.sh
    ```

4.  **Build and Run the Application:**
    ```bash
    docker-compose up --build
    ```

5.  **Access the App:**
    Open your web browser and go to **`http://localhost:5000`**.
