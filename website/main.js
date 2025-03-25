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
const serverUrl = "https://sentinel.ayaangrover.hackclub.app";

window.latestLiveData = {};

document.addEventListener('DOMContentLoaded', () => {
  const signInBtn = document.getElementById('googleSignIn');
  const dashboardDiv = document.getElementById('dashboard');
  const teacherInfoDiv = document.getElementById('teacherInfo');
  const studentsListDiv = document.getElementById('studentsList');
  const studentDetailsDiv = document.getElementById('studentDetails');

  function renderSignOutButton() {
    const signOutBtn = document.createElement("button");
    signOutBtn.textContent = "Sign Out";
    signOutBtn.className = "button";
    signOutBtn.addEventListener("click", () => auth.signOut());
    teacherInfoDiv.appendChild(signOutBtn);
  }

  function renderRulesManager() {
    const rulesManagerDiv = document.getElementById('rulesManager');
    if (!rulesManagerDiv) {
      console.error("No rules manager container found");
      return;
    }
    rulesManagerDiv.innerHTML = `
      <h3>Allowed Sites</h3>
      <p>Only sites listed below are allowed. All other sites are blocked.</p>
      <form id="rulesForm">
        <label for="siteUrl">Allowed Site URL:</label>
        <input type="text" id="siteUrl" placeholder="example.com" required />
        <br><br>
        <button type="submit" class="button">Add Allowed Site</button>
      </form>
      <div id="rulesList">
        <h4>Current Allowed Sites:</h4>
        <ul id="rulesUl"></ul>
      </div>
    `;

    const rulesForm = document.getElementById('rulesForm');
    const rulesUl = document.getElementById('rulesUl');

    rulesForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const siteUrl = document.getElementById('siteUrl').value.trim();
      if (!siteUrl) return;

      const newRule = {
        condition: { url: siteUrl },
        action: { type: "whitelist" }
      };

      let currentRules = [];
      try {
        const res = await fetch(`${serverUrl}/rules`);
        currentRules = await res.json();
      } catch (err) {
        console.error("Error fetching existing rules:", err);
      }

      currentRules.push(newRule);
      try {
        const res = await fetch(`${serverUrl}/rules`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rules: currentRules })
        });
        const text = await res.text();
        console.log("Rules updated:", text);
        fetchAndRenderRules();
      } catch (err) {
        console.error("Error updating rules:", err);
      }
    });

    async function fetchAndRenderRules() {
      try {
        const res = await fetch(`${serverUrl}/rules`);
        const rules = await res.json();
        rulesUl.innerHTML = "";
        rules.forEach((rule, index) => {
          const li = document.createElement("li");
          li.textContent = `Allowed Site: ${rule.condition.url} `;
          const deleteBtn = document.createElement("button");
          deleteBtn.textContent = "Delete";
          deleteBtn.className = "button";
          deleteBtn.addEventListener("click", async () => {
            const updatedRules = rules.filter((r, i) => i !== index);
            try {
              const res = await fetch(`${serverUrl}/rules`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ rules: updatedRules })
              });
              const text = await res.text();
              console.log("Rule deleted. Update response:", text);
              fetchAndRenderRules();
            } catch (err) {
              console.error("Error deleting rule:", err);
            }
          });
          li.appendChild(deleteBtn);
          rulesUl.appendChild(li);
        });
      } catch (err) {
        console.error("Error fetching rules:", err);
      }
    }
    fetchAndRenderRules();
  }

  function renderClearDataButton() {
    const clearBtn = document.createElement("button");
    clearBtn.textContent = "Clear All Data";
    clearBtn.className = "button";
    clearBtn.addEventListener("click", () => clearAllData());
    teacherInfoDiv.appendChild(clearBtn);
  }

  signInBtn.addEventListener('click', () => {
    const provider = new firebase.auth.GoogleAuthProvider();
    auth.signInWithPopup(provider).catch(error => console.error("Sign in error:", error));
  });

  auth.onAuthStateChanged(user => {
    if (user) {
      teacherInfoDiv.innerHTML = `<p>Welcome, ${user.displayName} (${user.email})</p>`;
      renderSignOutButton();
      renderClearDataButton();
      renderRulesManager();
      signInBtn.style.display = 'none';
      dashboardDiv.style.display = 'block';
      fetchStudents();
    } else {
      dashboardDiv.style.display = 'none';
      signInBtn.style.display = 'block';
    }
  });

  async function clearAllData() {
    try {
      const res = await fetch(`${serverUrl}/clear-entries`, { method: "DELETE" });
      const result = await res.text();
      console.log("Data cleared:", result);
      fetchStudents();
      studentDetailsDiv.innerHTML = "";
    } catch (error) {
      console.error("Error clearing data:", error);
    }
  }

  async function fetchStudents() {
    const firebaseSnapshot = await db.collection("students").get();
    let liveData = [];
    try {
      const res = await fetch(`${serverUrl}/students`);
      liveData = await res.json();
      liveData.forEach(student => {
        window.latestLiveData[student.userId] = student;
      });
    } catch (e) {
      console.error("Error fetching live data", e);
    }
    const liveMap = {};
    liveData.forEach(student => { liveMap[student.userId] = student; });
    renderStudentList(firebaseSnapshot.docs, liveMap);
  }

  function getDomainFromUrl(url) {
    try {
      const u = new URL(url);
      return u.hostname;
    } catch (e) {
      return url;
    }
  }

  function renderStudentList(studentDocs, liveMap) {
    studentsListDiv.innerHTML = "<h3>All Student Data</h3><div class='grid'>";
    studentDocs.forEach(doc => {
      const student = doc.data();
      const firebaseId = doc.id;
      const trackerId = student.trackerId ? student.trackerId : firebaseId;
      const liveInfo = liveMap[trackerId] || {};
      const domain = liveInfo.currentTab ? getDomainFromUrl(liveInfo.currentTab) : "No Active Page";
      
      const now = Date.now();
      const isActive = liveInfo.lastActivity && (now - liveInfo.lastActivity < 15000);
      const statusText = isActive ? "Active" : "Inactive";
      const statusClass = isActive ? "active" : "inactive";
      
      const displayName = student.displayName || student.email;
      
      const studentDiv = document.createElement("div");
      studentDiv.className = "student-entry";
      studentDiv.innerHTML = `
        <div class="student-header">
          <strong>${displayName}</strong>
          <span class="status" style="margin-left:10px;">
             <span class="status-dot ${statusClass}"></span> ${statusText}
          </span>
        </div>
        <div>Current Page: ${domain}</div>
        <div style="margin-top: 10px;">
          <img class="live-thumbnail" id="thumb-${trackerId}" src="" alt="Student may be distracted" style="width:100px; height:75px; object-fit:cover; border:1px solid #dee2e6;"/>
        </div>
        <div class="button-group" style="margin-top: 10px;">
          <button class="live-btn button small" data-id="${trackerId}" data-name="${displayName}">Large Preview</button>
          <button class="history-btn button small" data-id="${trackerId}" data-name="${displayName}">View History</button>
          <button class="delete-btn button small danger" data-id="${firebaseId}">Delete</button>
        </div>
      `;
      studentsListDiv.querySelector('.grid').appendChild(studentDiv);
    });
    studentsListDiv.innerHTML += "</div>";
    
    document.querySelectorAll('.history-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const studentId = e.target.getAttribute('data-id');
        const studentName = e.target.getAttribute('data-name');
        fetchStudentHistory(studentId, studentName);
      });
    });
    
    document.querySelectorAll('.live-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const studentId = e.target.getAttribute('data-id');
        const studentName = e.target.getAttribute('data-name');
        openLivePreview(studentId, studentName);
      });
    });
    
    document.querySelectorAll('.delete-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const studentDocId = e.target.getAttribute('data-id');
        deleteStudent(studentDocId);
      });
    });
  }
  
  function updateThumbnail(studentId) {
    fetch(`${serverUrl}/capture/latest?userId=${studentId}`)
      .then(res => res.json())
      .then(data => {
        const thumbImg = document.getElementById(`thumb-${studentId}`);
        if (data && data.screenshot && thumbImg) {
          thumbImg.src = data.screenshot;
        }
      })
      .catch(err => console.error("Error updating thumbnail for", studentId, err));
  }
  
  setInterval(() => {
    document.querySelectorAll('.live-thumbnail').forEach(img => {
      const id = img.id.replace("thumb-", "");
      updateThumbnail(id);
    });
  }, 5000);

  async function fetchStudentHistory(studentId, studentName) {
    try {
      const res = await fetch(`${serverUrl}/history?userId=${studentId}`);
      const history = await res.json();
    
      const filteredHistory = [];
      for (let i = 0; i < history.length; i++) {
        const currentEntry = history[i];
        let currentLabel = "";
        if (currentEntry.event) {
          switch (currentEntry.event) {
            case "window_blur":
              currentLabel = "Left Window";
              break;
            case "new_tab":
              currentLabel = "Opened New Tab";
              break;
            case "tab_switch":
              currentLabel = "Switched Tab";
              break;
            case "window_focus":
              currentLabel = "Focused Window";
              break;
            default:
              currentLabel = getDomainFromUrl(currentEntry.tabVisited);
          }
        } else {
          currentLabel = getDomainFromUrl(currentEntry.tabVisited);
        }
        let previousLabel = "";
        if (i > 0) {
          const prevEntry = history[i - 1];
          if (prevEntry.event) {
            switch (prevEntry.event) {
              case "window_blur":
                previousLabel = "Left Window";
                break;
              case "new_tab":
                previousLabel = "Opened New Tab";
                break;
              case "tab_switch":
                previousLabel = "Switched Tab";
                break;
              case "window_focus":
                previousLabel = "Focused Window";
                break;
              default:
                previousLabel = getDomainFromUrl(prevEntry.tabVisited);
            }
          } else {
            previousLabel = getDomainFromUrl(prevEntry.tabVisited);
          }
        }
        if (i === 0 || currentLabel !== previousLabel) {
          filteredHistory.push(currentEntry);
        }
      }
    
      let historyHTML = `<h4>Browsing History for ${studentName}:</h4><ul>`;
      if (filteredHistory.length === 0) {
        historyHTML += "<li>No recent activity available.</li>";
      } else {
        filteredHistory.forEach(item => {
          const time = new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
          let label = "";
          if (item.event) {
            switch (item.event) {
              case "window_blur":
                label = "Left Window";
                break;
              case "new_tab":
                label = "Opened New Tab";
                break;
              case "tab_switch":
                label = "Switched Tab";
                break;
              case "window_focus":
                label = "Focused Window";
                break;
              default:
                label = getDomainFromUrl(item.tabVisited);
            }
          } else {
            label = getDomainFromUrl(item.tabVisited);
          }
          historyHTML += `<li><strong>${time}</strong> ${label}</li>`;
        });
      }
      historyHTML += "</ul>";
      studentDetailsDiv.innerHTML = historyHTML;
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  }

  async function deleteStudent(studentDocId) {
    try {
      await db.collection("students").doc(studentDocId).delete();
      console.log("Student deleted:", studentDocId);
      fetchStudents();
      studentDetailsDiv.innerHTML = "";
    } catch (error) {
      console.error("Error deleting student:", error);
    }
  }

  function openLivePreview(studentId, studentName) {
    let modal = document.getElementById("livePreviewModal");
    if (!modal) {
      modal = document.createElement("div");
      modal.id = "livePreviewModal";
      modal.style.position = "fixed";
      modal.style.top = "10%";
      modal.style.left = "10%";
      modal.style.width = "80%";
      modal.style.height = "80%";
      modal.style.background = "#fff";
      modal.style.border = "2px solid #0057e7";
      modal.style.zIndex = 10000;
      modal.style.padding = "10px";
      modal.style.overflow = "hidden";
      modal.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <h3 id="modalHeader"></h3>
          <button id="closeModal" class="button">Close</button>
        </div>
        <div id="livePreviewContainer" style="width:100%; height:90%; display:flex; justify-content:center; align-items:center;">
          <img id="liveImg" style="width:100%; height:100%; object-fit:contain;" src="" alt="Live Preview"/>
        </div>
      `;
      document.body.appendChild(modal);
      
      document.getElementById("closeModal").addEventListener("click", () => {
        clearInterval(modal.refreshInterval);
        modal.remove();
      });
    }
    
    document.getElementById("modalHeader").textContent = `Live Preview: ${studentName}`;
    const liveImg = document.getElementById("liveImg");
    
    function updateLivePreview() {
      fetch(`${serverUrl}/capture/latest?userId=${studentId}`)
        .then(res => res.json())
        .then(data => {
          if (data && data.screenshot) {
            liveImg.src = data.screenshot;
          }
        })
        .catch(err => {
          console.error("Error fetching live capture:", err);
        });
    }
    
    updateLivePreview();
    // dont set this below 1000ms, chrome limits this to 1/second
    modal.refreshInterval = setInterval(updateLivePreview, 1000);
  }

  setInterval(() => { if (auth.currentUser) fetchStudents(); }, 10000);
});