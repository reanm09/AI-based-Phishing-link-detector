# 🛡️ Phishing & Scam Detector 🔍  

A **Chrome Extension** that helps detect phishing websites using **Google Safe Browsing API**, **PhishTank database**, and a **custom Machine Learning Model**. Stay protected from online threats while browsing! 🚀  

---

## 🎯 Features  
👉 **Google Safe Browsing Check** – Detects dangerous sites instantly  
👉 **PhishTank Database Lookup** – Identifies known phishing sites  
👉 **Machine Learning Model** – Predicts suspicious websites using AI  
👉 **One-Click Scan** – Quick and easy website verification  
👉 **Lightweight & Fast** – Minimal impact on browser performance  

---

## 🖼️ Screenshots  
> 📌 ![image](https://github.com/user-attachments/assets/fdbda19a-47a4-46e1-b0b6-1681f6b67153)


---

## 🛠️ Installation  

### **Method 1: Load as Unpacked Extension**  
1. **Download or Clone** this repository:  
   ```sh
   git clone https://github.com/reanm09/AI-based-Phishing-link-detector.git
   ```
2. Open **Google Chrome** and navigate to:  
   ```
   chrome://extensions/
   ```
3. **Enable Developer Mode** (Toggle in the top-right corner)  
4. Click **"Load unpacked"** and select the downloaded folder  
5. The extension is now ready to use!  

---

## 🚀 How to Use  
1. Visit any website  
2. Click on the **Phishing Detector** extension icon  
3. Press **"Check This Page"**  
4. The extension will:
   - ✅ Query **Google Safe Browsing API**
   - ✅ Lookup the site in **PhishTank Database**
   - ✅ Run the **Machine Learning Model**  
5. If flagged, you'll see a **warning** ⚠️  

---

## ⚙️ How It Works  
- **Step 1:** Checks if the website is flagged by **Google Safe Browsing API**  
- **Step 2:** Searches for the website in the **PhishTank database**  
- **Step 3:** Runs the **Machine Learning model** for an additional threat assessment  
- **Step 4:** Displays **Safe** ✅ or **Phishing Warning** ⚠️  

---

## 🔧 Technologies Used  
- **JavaScript (Chrome Extension API)**  
- **Google Safe Browsing API**  
- **PhishTank Database**  
- **TensorFlow.js (Machine Learning Model)**  
- **ONNX Runtime (Model Optimization)**  

---

## 🏆 Why This Extension?  
👉 **Multi-Layered Security** – Combines API checks, databases, and AI  
👉 **Real-Time Phishing Detection** – No delay in response  
👉 **Privacy-Focused** – No user data is stored or shared  

---

## 🔥 Future Improvements  
- ✅ Implement **automatic blocking** of flagged sites  
- ✅ Train **a more advanced ML model** for higher accuracy  
- ✅ Enhance **User Interface & Experience**  

---

## 🤝 Contributing  
Want to contribute? **Fork this repo**, make changes, and submit a **pull request**! Contributions are highly appreciated.  

---

## 🛋️ Packing the Extension  
To **package the extension** into a `.zip` for easy sharing:  
1. Navigate to the extension folder  
2. Run the following command:  
   ```sh
   zip -r phishing_detector.zip .
   ```  
3. Now you can distribute `phishing_detector.zip` or load it manually!  

---

## 📝 License  
This project is **MIT Licensed** – Free to use, modify, and improve.  

---

💡 *Developed for a hackathon! Feel free to enhance and customize it!* 🚀

