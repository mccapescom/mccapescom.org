const authContainer = document.getElementById('auth-container');
const listingsDiv = document.getElementById('listings');
const authBtn = document.getElementById('auth-btn');
const logoutBtn = document.getElementById('logout-btn');
const authError = document.getElementById('auth-error');
const capeList = document.getElementById('cape-list');
const toggleAuthBtn = document.getElementById('toggle-auth');
const formTitle = document.getElementById('form-title');
const registerExtra = document.getElementById('register-extra');

let isLogin = true; // toggle between login and register

function saveToken(token) {
  localStorage.setItem('token', token);
}

function getToken() {
  return localStorage.getItem('token');
}

function clearToken() {
  localStorage.removeItem('token');
}

async function fetchListings() {
//   try {
//     const token = getToken();
//     const res = await fetch('/api/user/listings', {
//       headers: { 'Authorization': 'Bearer ' + token }
//     });
//     if (res.status === 401) throw new Error('Unauthorized');
//     if (!res.ok) throw new Error('Failed to fetch listings');
//     const data = await res.json();
//     capeList.innerHTML = '';
//     if (data.length === 0) capeList.innerHTML = '<p>No community listings found.</p>';
//     else {
//       data.forEach(cape => {
//         const card = document.createElement('div');
//         card.className = 'cape-card';
//         card.innerHTML = `
//           <h3>${cape.name}</h3>
//           <p>${cape.description}</p>
//           <small>Type: ${cape.type.toUpperCase()}</small>
//         `;
//         capeList.appendChild(card);
//       });
//     }
//   } catch (err) {
//     alert(err.message);
//     logout();
//   }
}

async function login(username, password) {
  const res = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error('Login failed');
  const data = await res.json();
  saveToken(data.token);
}

async function register(username, password) {
  const res = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const errData = await res.json();
    throw new Error(errData.message || 'Registration failed');
  }
  // On success, auto-login below
}

async function handleAuth() {
  authError.textContent = '';
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();

  if (!username || !password) {
    authError.textContent = 'Please enter username and password';
    return;
  }

  if (!isLogin) {
    // Register flow
    const passwordConfirm = document.getElementById('password-confirm').value.trim();
    if (password !== passwordConfirm) {
      authError.textContent = 'Passwords do not match';
      return;
    }
    try {
      await register(username, password);
      // After successful registration, login automatically
      await login(username, password);
      showListings();
    } catch (err) {
      authError.textContent = err.message;
    }
  } else {
    // Login flow
    try {
      await login(username, password);
      showListings();
    } catch (err) {
      authError.textContent = err.message;
    }
  }
}

function logout() {
  clearToken();
  listingsDiv.style.display = 'none';
  authContainer.style.display = 'block';
  authError.textContent = '';
  // Reset inputs
  document.getElementById('username').value = '';
  document.getElementById('password').value = '';
  if (!isLogin) toggleToLogin();
}

function showListings() {
  authContainer.style.display = 'none';
  listingsDiv.style.display = 'block';
  fetchListings();
}

function toggleToRegister() {
  isLogin = false;
  formTitle.textContent = 'Register a new account';
  authBtn.textContent = 'Register';
  toggleAuthBtn.textContent = 'Already have an account? Login here';
  registerExtra.style.display = 'block';
}

function toggleToLogin() {
  isLogin = true;
  formTitle.textContent = 'Login to see your listings';
  authBtn.textContent = 'Login';
  toggleAuthBtn.textContent = "Don't have an account? Register here";
  registerExtra.style.display = 'none';
}

toggleAuthBtn.onclick = () => {
  if (isLogin) toggleToRegister();
  else toggleToLogin();
};

authBtn.onclick = handleAuth;
logoutBtn.onclick = logout;

// On load: if token present, try to fetch listings directly
if (getToken()) {
  showListings();
}

const showCreateBtn = document.getElementById('show-create-btn');
const createForm = document.getElementById('create-listing-form');
const createBtn = document.getElementById('create-listing-btn');
const cancelCreateBtn = document.getElementById('cancel-create-btn');
const createError = document.getElementById('create-error');

showCreateBtn.onclick = () => {
  createForm.style.display = 'block';
  showCreateBtn.style.display = 'none';
  createError.textContent = '';
  // Clear inputs
  document.getElementById('new-name').value = '';
  document.getElementById('new-description').value = '';
  document.getElementById('new-type').value = '';
};

cancelCreateBtn.onclick = () => {
  createForm.style.display = 'none';
  showCreateBtn.style.display = 'inline-block';
  createError.textContent = '';
};

createBtn.onclick = async () => {
  createError.textContent = '';
  const name = document.getElementById('new-name').value.trim();
  const description = document.getElementById('new-description').value.trim();
  const type = document.getElementById('new-type').value;

  if (!name || !description || !type) {
    createError.textContent = 'Please fill in all fields.';
    return;
  }

  try {
    const token = getToken();
    const res = await fetch('/offers', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ name, description, type })
    });

    if (!res.ok) {
      const errData = await res.json();
      throw new Error(errData.message || 'Failed to create listing');
    }

    // Success: refresh listings and hide form
    createForm.style.display = 'none';
    showCreateBtn.style.display = 'inline-block';
    fetchListings();

  } catch (err) {
    createError.textContent = err.message;
  }
};
