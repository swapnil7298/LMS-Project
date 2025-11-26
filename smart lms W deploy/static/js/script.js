// This function must remain outside the DOMContentLoaded listener to be globally accessible
function openTab(evt, tabName) {
    const tabcontent = document.getElementsByClassName("tab-content");
    for (let i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    const tablinks = document.getElementsByClassName("tab-link");
    for (let i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    if(evt) evt.currentTarget.className += " active";
}


document.addEventListener('DOMContentLoaded', () => {

    // --- 1. THEME TOGGLER ---
const themeToggleBtn = document.getElementById('theme-toggle');
const body = document.body;
if (themeToggleBtn) {
    themeToggleBtn.addEventListener('click', () => {
        body.classList.toggle('dark-mode');
        localStorage.setItem('theme', body.classList.contains('dark-mode') ? 'dark' : 'light');
    });
}

    // --- 2. PASSWORD VISIBILITY TOGGLE ---
    document.querySelectorAll('.password-toggle-icon').forEach(icon => {
        icon.addEventListener('click', () => {
            const passwordInput = icon.previousElementSibling;
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                icon.classList.replace('fa-eye-slash', 'fa-eye');
            } else {
                passwordInput.type = 'password';
                icon.classList.replace('fa-eye', 'fa-eye-slash');
            }
        });
    });
    
    // --- 3. DISMISSIBLE FLASH MESSAGES (NEW) ---
    document.querySelectorAll('.alert .btn-close').forEach(button => {
        button.addEventListener('click', function () {
            this.closest('.alert').style.display = 'none';
        });
    });

    // --- 4. AJAX: DELETE MATERIAL (NEW) ---
    document.querySelectorAll('.delete-material-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            if (confirm('Are you sure you want to delete this material?')) {
                fetch(this.action, { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        this.closest('.material-item').remove();
                    } else {
                        alert('Error: ' + data.message);
                    }
                })
                .catch(err => console.error("Fetch Error:", err));
            }
        });
    });

    // --- 5. AJAX: ADMIN USER ACTIONS (NEW) ---
    document.querySelectorAll('.role-change-btn').forEach(button => {
        button.addEventListener('click', function() {
            const newRole = this.dataset.role;
            const form = this.closest('form');
            fetch(form.action, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ new_role: newRole })
            })
            .then(response => response.json())
            .then(data => {
                if(data.success) {
                    // Easiest way to show the updated state is to reload
                    window.location.reload();
                } else {
                    alert('Error: ' + data.message);
                }
            });
        });
    });

    document.querySelectorAll('.ban-toggle-form').forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            fetch(this.action, { method: 'POST'})
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const row = this.closest('tr');
                    const button = this.querySelector('button');
                    row.classList.toggle('banned-user', data.is_banned);
                    button.textContent = data.is_banned ? 'Unban' : 'Ban';
                    button.classList.toggle('btn-secondary', data.is_banned);
                    button.classList.toggle('btn-warning', !data.is_banned);
                } else {
                    alert('Error: ' + data.message);
                }
            });
        });
    });
    
    // --- 6. UNIVERSAL CHATBOT LOGIC (RESTORED) ---
    const floatingChatbotButton = document.getElementById('chatbot-toggle');
    const geminiChatWindow = document.getElementById('chatbot-window');
    const closeGeminiChat = document.getElementById('close-chatbot');

    if (floatingChatbotButton && geminiChatWindow) {
        floatingChatbotButton.addEventListener('click', () => {
            geminiChatWindow.classList.toggle('open');
        });
    }

    if (closeGeminiChat) {
        closeGeminiChat.addEventListener('click', () => geminiChatWindow.classList.remove('open'));
    }

    // --- 7. CHATBOT FUNCTIONALITY (RESTORED) ---
    function addChatMessage(text, sender, container, isLoading = false) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('chat-message', `${sender}-message`);
        if (isLoading) messageElement.classList.add('loading');
        const p = document.createElement('p');
        p.textContent = text;
        messageElement.appendChild(p);
        container.appendChild(messageElement);
        container.scrollTop = container.scrollHeight;
        return messageElement;
    }

    // General Gemini Chatbot
    const chatbotInput = document.getElementById('chatbot-input');
    const chatbotSend = document.getElementById('chatbot-send');
    const chatbotBody = document.getElementById('chatbot-body');
    if (chatbotInput && chatbotSend && chatbotBody) {
        const sendGeminiMessage = async () => {
            const prompt = chatbotInput.value.trim();
            if (prompt === '') return;
            addChatMessage(prompt, 'user', chatbotBody);
            chatbotInput.value = '';
            const loadingMessage = addChatMessage('Thinking...', 'bot', chatbotBody, true);
            try {
                const response = await fetch('/api/gemini-chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt: prompt }),
                });
                const data = await response.json();
                loadingMessage.querySelector('p').textContent = data.response || 'Sorry, an error occurred.';
            } catch (error) {
                loadingMessage.querySelector('p').textContent = 'Sorry, an error occurred.';
            } finally {
                loadingMessage.classList.remove('loading');
            }
        };
        chatbotSend.addEventListener('click', sendGeminiMessage);
        chatbotInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendGeminiMessage(); });
    }
    
    // Course-Specific Chatbot
    const courseChatInput = document.getElementById('course-chat-input');
    const courseChatSend = document.getElementById('course-chat-send');
    const courseChatBody = document.getElementById('course-chat-body');
    if (courseChatInput && courseChatSend && courseChatBody) {
        const courseId = courseChatInput.dataset.courseId;
        const sendCourseMessage = async () => {
            const prompt = courseChatInput.value.trim();
            if (prompt === '' || !courseId) return;
            addChatMessage(prompt, 'user', courseChatBody);
            courseChatInput.value = '';
            const loadingMessage = addChatMessage('Searching materials...', 'bot', courseChatBody, true);
            try {
                const response = await fetch('/api/course-chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt: prompt, course_id: courseId }),
                });
                const data = await response.json();
                loadingMessage.querySelector('p').textContent = data.answer || 'Sorry, an error occurred.';
            } catch (error) {
                loadingMessage.querySelector('p').textContent = 'Sorry, an error occurred.';
            } finally {
                loadingMessage.classList.remove('loading');
            }
        };
        courseChatSend.addEventListener('click', sendCourseMessage);
        courseChatInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendCourseMessage(); });
    }

    // --- 8. NOTIFICATION CLEARING LOGIC (RESTORED) ---
    const notificationsList = document.querySelector('.notifications-list');
    if (notificationsList && notificationsList.querySelector('.unread')) {
        setTimeout(() => {
            fetch('/notifications/mark-as-read', { method: 'POST' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const notificationCount = document.querySelector('.notification-count');
                    if (notificationCount) notificationCount.style.display = 'none';
                }
            });
        }, 2000); // Wait 2 seconds before marking as read
    }

    // --- 9. MATERIAL VIEW TRACKING (FROM PHASE 2) ---
    document.querySelectorAll('.material-view-link').forEach(link => {
        link.addEventListener('click', () => {
            const materialId = link.dataset.materialId;
            if (materialId) {
                fetch('/api/log-material-view', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ material_id: materialId }),
                }).catch(error => console.error('Failed to log material view:', error));
            }
        });
    });

    // --- 10. LOGIN METHOD TOGGLE (RESTORED) ---
    const toggleLoginMethodLink = document.getElementById('toggle-login-method');
    if (toggleLoginMethodLink) {
        const passwordField = document.getElementById('password-field');
        const loginMethodInput = document.getElementById('login_method');
        const loginButton = document.getElementById('login-button');

        if (passwordField) passwordField.style.display = 'none';

        toggleLoginMethodLink.addEventListener('click', (e) => {
            e.preventDefault();
            if (loginMethodInput.value === 'otp') {
                passwordField.style.display = 'block';
                loginMethodInput.value = 'password';
                loginButton.textContent = 'Login';
                toggleLoginMethodLink.textContent = 'Login with OTP instead';
            } else {
                passwordField.style.display = 'none';
                loginMethodInput.value = 'otp';
                loginButton.textContent = 'Send Login Code';
                toggleLoginMethodLink.textContent = 'Login with Password instead';
            }
        });
    }
    
    // --- 11. TAB SWITCHING LOGIC ---
    const firstTab = document.querySelector('.tab-link');
    if (firstTab) {
        firstTab.click();
    }
});
// DELETE THIS ENTIRE BLOCK

// --- 9. NEW: SUMMARIZER LOGIC ---
document.querySelectorAll('.summarize-btn').forEach(button => {
  button.addEventListener('click', async (e) => {
    e.preventDefault();
    const materialId = e.target.dataset.materialId;
    
    // You would typically show this in a nice modal window
    alert('Generating summary... This may take a moment.');

    try {
        const response = await fetch('/api/summarize-material', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ material_id: materialId }),
        });
        if (!response.ok) throw new Error('Failed to get summary');
        const data = await response.json();
        
        // For now, we just show the summary in an alert
        alert(`Summary:\n\n${data.summary}`);

    } catch (error) {
        console.error("Summarization error:", error);
        alert('Sorry, an error occurred while generating the summary.');
    }
  });
});