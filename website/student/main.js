const firebaseConfig = {
  apiKey: "AIzaSyC7Nzoe0pctRTmSboQNbSxxAzkYahFNtWw",
  authDomain: "sentinel-tracker-8.firebaseapp.com",
  projectId: "sentinel-tracker-8",
  storageBucket: "sentinel-tracker-8.firebasestorage.app",
  messagingSenderId: "1004030770470",
  appId: "1:1004030770470:web:724f8dbece36e79d6a15e7"
};

firebase.initializeApp(firebaseConfig);
const auth = firebase.auth();
const db = firebase.firestore();

document.addEventListener('DOMContentLoaded', () => {
  const activityDiv = document.getElementById("activity");
  const loginSection = document.getElementById("loginSection");

  function renderSignInButton() {
    loginSection.innerHTML = "";
    const signInBtn = document.createElement("button");
    signInBtn.className = "button";
    signInBtn.textContent = "Sign in with Google";
    signInBtn.addEventListener("click", () => {
      const provider = new firebase.auth.GoogleAuthProvider();
      auth.signInWithPopup(provider).catch(error => {
        console.error("Student sign in error:", error);
        activityDiv.innerHTML = `<p>Sign in error. Please try again.</p>`;
      });
    });
    loginSection.appendChild(signInBtn);
  }

  function renderSignOutButton() {
    const signOutBtn = document.createElement("button");
    signOutBtn.className = "button";
    signOutBtn.textContent = "Sign Out";
    signOutBtn.addEventListener("click", () => auth.signOut());
    loginSection.appendChild(signOutBtn);
  }

  auth.onAuthStateChanged(async user => {
    if (user && chrome && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage("kmcbdpnhhiaobekbealpdpabppbpfeah", { studentId: user.uid }, response => {
        console.log("Extension responded:", response);
      });
    }

    if (user) {
      if (chrome && chrome.storage) {
        chrome.storage.local.set({ studentId: user.uid });
      }
      try {
        await db.collection("students").doc(user.uid).set({
          email: user.email,
          displayName: user.displayName || user.email,
          updatedAt: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      } catch (err) {
        console.error("Error updating student record:", err);
      }
      activityDiv.innerHTML = `
          <p>Welcome, ${user.displayName || user.email}!</p>
          <p>Email: ${user.email}</p>
          <div class="status">
            <div class="status-dot"></div>
            <span>Active Session</span>
          </div>
        `;
      loginSection.innerHTML = "";
      renderSignOutButton();
    } else {
      activityDiv.innerHTML = `<p>Please sign in to view your session.</p>`;
      renderSignInButton();
    }
  });
});