async function loadAuthUI() {
  const token = localStorage.getItem("token");

  const authContainer = document.getElementById("auth-container");
  const profileEmail = document.getElementById("profile-email");

  if (!token) {
    authContainer.style.display = "block";
    return;
  }

  try {
    const res = await fetch("/profile", {
      headers: {
        "Authorization": "Bearer " + token
      }
    });

    if (!res.ok) throw new Error("Invalid token");

    const user = await res.json();

    authContainer.innerHTML = `
      <div class="dropdown">
        <button class="dropdown-toggle">${user.email} ▾</button>
        <ul class="dropdown-menu">
          <li><a href="#">Dashboard</a></li>
          <li><a href="#" onclick="logout()">Logout</a></li>
        </ul>
      </div>
    `;
  } catch {
    localStorage.removeItem("token");
    location.reload();
  }
}

function logout() {
  localStorage.removeItem("token");
  window.location.href = "/";
}

document.addEventListener("DOMContentLoaded", loadAuthUI);
