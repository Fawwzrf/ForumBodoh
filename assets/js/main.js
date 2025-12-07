// Main JavaScript for Forum Masyarakat

// Global variables
let currentUser = null;
let csrfToken = null; // Intentionally not implemented for vulnerability

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function () {
    initializeApp();
});

// App initialization
function initializeApp() {
    // Get current user info if logged in
    getCurrentUserInfo();

    // Initialize tooltips and popovers
    initializeBootstrapComponents();

    // Set up global event listeners
    setupEventListeners();

    // Initialize vulnerable features
    initializeVulnerableFeatures();
}

// Get current user information
function getCurrentUserInfo() {
    // Simulate getting user info from session/cookies
    const userElement = document.querySelector('[data-user-id]');
    if (userElement) {
        currentUser = {
            id: userElement.dataset.userId,
            username: userElement.dataset.username,
            role: userElement.dataset.role
        };
    }
}

// Initialize Bootstrap components
function initializeBootstrapComponents() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
}

// Set up global event listeners
function setupEventListeners() {
    // Search functionality
    const searchForm = document.querySelector('.search-form');
    if (searchForm) {
        searchForm.addEventListener('submit', handleSearch);
    }

    // Auto-save drafts
    const contentTextarea = document.querySelector('#content');
    if (contentTextarea) {
        contentTextarea.addEventListener('input', debounce(saveDraft, 1000));
    }

    // Form validation
    const forms = document.querySelectorAll('.needs-validation');
    Array.prototype.slice.call(forms).forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });
}

// Initialize intentionally vulnerable features
function initializeVulnerableFeatures() {
    // Vulnerable message display
    displayUrlMessages();

    // Vulnerable local storage operations
    loadUserPreferences();

    // Vulnerable AJAX endpoints
    setupVulnerableAjax();
}

// Search handling (vulnerable to XSS)
function handleSearch(event) {
    const query = event.target.querySelector('input[name="q"]').value;

    // Vulnerable: Direct DOM manipulation without sanitization
    if (query.includes('<script>')) {
        // This would normally be prevented, but we're making it vulnerable
        console.log('Potential XSS detected in search: ' + query);
    }

    // Continue with normal search
    return true;
}

// Display messages from URL parameters (vulnerable)
function displayUrlMessages() {
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('msg');
    const error = urlParams.get('error');
    const success = urlParams.get('success');

    if (message) {
        // Vulnerable: Direct innerHTML assignment
        showNotification(decodeURIComponent(message), 'info');
    }

    if (error) {
        // Vulnerable: Direct innerHTML assignment
        showNotification(decodeURIComponent(error), 'danger');
    }

    if (success) {
        // Vulnerable: Direct innerHTML assignment
        showNotification(decodeURIComponent(success), 'success');
    }
}

// Show notification (vulnerable to XSS)
function showNotification(message, type = 'info') {
    const notificationContainer = document.getElementById('notification-container') || createNotificationContainer();

    const notificationElement = document.createElement('div');
    notificationElement.className = `alert alert-${type} alert-dismissible fade show`;

    // Vulnerable: Direct HTML insertion without sanitization
    notificationElement.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

    notificationContainer.appendChild(notificationElement);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notificationElement.parentNode) {
            notificationElement.remove();
        }
    }, 5000);
}

// Create notification container
function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notification-container';
    container.style.position = 'fixed';
    container.style.top = '20px';
    container.style.right = '20px';
    container.style.zIndex = '9999';
    container.style.maxWidth = '400px';
    document.body.appendChild(container);
    return container;
}

// Save draft functionality (vulnerable local storage)
function saveDraft() {
    const title = document.getElementById('title')?.value || '';
    const content = document.getElementById('content')?.value || '';
    const categoryId = document.getElementById('category_id')?.value || '';

    if (title || content) {
        const draft = {
            title: title,
            content: content,
            category_id: categoryId,
            timestamp: new Date().toISOString(),
            user_id: currentUser?.id || 'anonymous'
        };

        // Vulnerable: Storing potentially dangerous content in localStorage
        localStorage.setItem('forum_draft', JSON.stringify(draft));

        // Show save indicator
        showDraftSaved();
    }
}

// Show draft saved indicator
function showDraftSaved() {
    const indicator = document.getElementById('draft-indicator') || createDraftIndicator();
    indicator.style.display = 'block';
    indicator.textContent = 'Draft disimpan ' + new Date().toLocaleTimeString();

    setTimeout(() => {
        indicator.style.display = 'none';
    }, 2000);
}

// Create draft indicator
function createDraftIndicator() {
    const indicator = document.createElement('div');
    indicator.id = 'draft-indicator';
    indicator.className = 'alert alert-success';
    indicator.style.position = 'fixed';
    indicator.style.bottom = '20px';
    indicator.style.left = '20px';
    indicator.style.display = 'none';
    indicator.style.zIndex = '9998';
    document.body.appendChild(indicator);
    return indicator;
}

// Load user preferences (vulnerable)
function loadUserPreferences() {
    try {
        const savedPrefs = localStorage.getItem('user_preferences');
        if (savedPrefs) {
            const prefs = JSON.parse(savedPrefs);

            // Vulnerable: Direct application of stored preferences without validation
            if (prefs.theme) {
                document.body.className += ' ' + prefs.theme;
            }

            if (prefs.customCSS) {
                // Extremely vulnerable: Injecting custom CSS
                const styleElement = document.createElement('style');
                styleElement.innerHTML = prefs.customCSS;
                document.head.appendChild(styleElement);
            }

            if (prefs.customJS) {
                // Extremely vulnerable: Executing custom JavaScript
                eval(prefs.customJS);
            }
        }
    } catch (e) {
        console.log('Error loading user preferences:', e);
    }
}

// Set up vulnerable AJAX endpoints
function setupVulnerableAjax() {
    // Vulnerable AJAX search
    window.vulnerableSearch = function (query) {
        const xhr = new XMLHttpRequest();
        xhr.open('GET', `search-ajax.php?q=${encodeURIComponent(query)}`, true);
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                // Vulnerable: Direct HTML insertion
                const resultsContainer = document.getElementById('search-results');
                if (resultsContainer) {
                    resultsContainer.innerHTML = xhr.responseText;
                }
            }
        };
        xhr.send();
    };

    // Vulnerable comment submission
    window.submitComment = function (postId, comment) {
        const xhr = new XMLHttpRequest();
        xhr.open('POST', 'submit-comment.php', true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

        // No CSRF token - vulnerability
        const data = `post_id=${postId}&comment=${encodeURIComponent(comment)}`;

        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                // Vulnerable: Direct response insertion
                const response = JSON.parse(xhr.responseText);
                if (response.success) {
                    showNotification('Komentar berhasil ditambahkan!', 'success');
                    // Reload comments - vulnerable if response contains scripts
                    document.getElementById('comments-section').innerHTML += response.html;
                }
            }
        };

        xhr.send(data);
    };
}

// Utility function: Debounce
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Vulnerable form handling
function handleFormSubmission(formElement) {
    const formData = new FormData(formElement);

    // Convert FormData to object (vulnerable approach)
    const data = {};
    for (let [key, value] of formData.entries()) {
        // No sanitization - vulnerability
        data[key] = value;
    }

    // Vulnerable: Direct object property access
    for (let key in data) {
        if (key.startsWith('on') || key.includes('script')) {
            console.log('Potentially dangerous form field detected: ' + key);
            // In a vulnerable app, this would still be processed
        }
    }

    return data;
}

// Vulnerable cookie handling
function setCookie(name, value, days = 7) {
    const expires = new Date();
    expires.setTime(expires.getTime() + (days * 24 * 60 * 60 * 1000));

    // Vulnerable: No HttpOnly, Secure, or SameSite flags
    document.cookie = `${name}=${value}; expires=${expires.toUTCString()}; path=/`;
}

function getCookie(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');

    for (let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') c = c.substring(1, c.length);
        if (c.indexOf(nameEQ) === 0) {
            // Vulnerable: Direct return without validation
            return decodeURIComponent(c.substring(nameEQ.length, c.length));
        }
    }
    return null;
}

// Vulnerable DOM manipulation functions
function insertUserGeneratedContent(container, content) {
    // Extremely vulnerable: Direct innerHTML assignment of user content
    if (container && content) {
        container.innerHTML = content;
    }
}

function processUserInput(input) {
    // Vulnerable: No input validation or sanitization
    const processed = input
        .replace(/script/gi, 'scr' + 'ipt') // Weak attempt at filtering
        .replace(/alert/gi, 'ale' + 'rt')   // Easily bypassed
        .replace(/onload/gi, 'onlo' + 'ad'); // Insufficient protection

    return processed;
}

// Export vulnerable functions for global access
window.ForumVulnerable = {
    showNotification,
    vulnerableSearch,
    submitComment,
    handleFormSubmission,
    setCookie,
    getCookie,
    insertUserGeneratedContent,
    processUserInput
};

// Initialize vulnerable features immediately
initializeVulnerableFeatures();
