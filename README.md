**Post-Quantum Cryptography: Transitioning from RSA to CRYSTALS-Kyber

📌 Project Overview

This project demonstrates the vulnerability of classical Public Key Cryptography (RSA) in the era of Quantum Computing and implements a Post-Quantum Cryptography (PQC) solution using CRYSTALS-Kyber (ML-KEM) and AES-256.

The application is a Hybrid Cryptographic Simulator built with Python (Flask) and a Web Dashboard. It consists of two core modules:

The Attack (RSA): Simulates a Quantum Computer using Shor's Algorithm to factor large integers and break RSA encryption.

The Defense (Kyber + AES): Demonstrates a secure key exchange using Lattice-based cryptography (Kyber) which is resistant to quantum attacks.

🚀 Features

Interactive RSA Key Generation: Users can input custom Prime Numbers ($p, q$) and Messages.

Shor's Algorithm Simulation: Visualizes how a Quantum Computer finds the period ($r$) of a function to derive private keys.

Post-Quantum Key Exchange: Simulates the Kyber-768 parameter set (NIST Security Level 3).

Hybrid Security: Combines Kyber (for key exchange) with AES-256 (for data encryption).

Web-Based Dashboard: A "Hacker-Style" UI to visualize the attack and defense in real-time.

🛠️ Technology Stack

Backend: Python 3.10+ (Flask Framework)

Frontend: HTML5, CSS3, JavaScript (Fetch API)

Cryptography: - PyCryptodome (for AES and RSA math)

Hashlib (for SHA-256)

Custom implementations for Shor's Period Finding & Kyber Logic simulation.

⚙️ Installation Guide

Prerequisites

Ensure you have Python installed. You can check by running:

py --version


Step 1: Install Dependencies

Open your terminal/command prompt and run:

py -m pip install flask pycryptodome


Step 2: Project Structure

Ensure your folder looks exactly like this:

/PQC_Project
│
├── app.py                # Main Python Application (Backend)
├── README.md             # This documentation file
└── templates/            # Folder for HTML files
    └── index.html        # The Website Interface


▶️ How to Run

Open your terminal in the project folder.

Run the application:

py app.py


You will see a message: Running on http://127.0.0.1:5000.

Open your web browser (Chrome/Edge) and go to:
https://www.google.com/search?q=http://127.0.0.1:5000

📖 Usage Manual

Module 1: RSA Vulnerability (The Attack)

Enter a secret message (e.g., "Bank Password").

Enter two small prime numbers (e.g., 17 and 19). Note: Keep numbers small for the simulation to run instantly.

Click "Generate Keys & Hack!".

Observation: The system will generate a Public Key, encrypt your message, and then the "Quantum Simulator" will calculate the period $r$, derive the private key, and decrypt your message without permission.

Module 2: Kyber Solution (The Defense)

Scroll to the Post-Quantum section.

Click "Initiate Secure Transfer".

Observation: The system generates a Lattice-based public key (represented as a vector). The simulated attacker fails to find a period, and a shared secret is securely established to encrypt the data using AES.

🔮 Future Scope

Hardware Integration: Running the period-finding function on a real IBM Quantum Processor using Qiskit.

True Hybrid Mode: Implementing a full TLS 1.3 handshake combining ECDH (X25519) and Kyber-768.

Memory Optimization: Reducing the stack usage of Kyber for embedded IoT devices (Cortex-M4).

👥 Authors

Polavarapu Ramani

Dachepalli Nikhitha

Sriramadasu Shivani

Gavini. Murali Krishna

Dr. Gogineni Rajesh Chandra (Guide)

Submitted as part of the Final Year Project for the Department of ACSE, VLITS.**
