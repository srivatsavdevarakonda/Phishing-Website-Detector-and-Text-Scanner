// Tab switching logic
function openTab(event, tabName) {
    let i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tab-content");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].classList.remove("active");
    }
    tablinks = document.getElementsByClassName("tab-link");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].classList.remove("active");
    }
    document.getElementById(tabName).classList.add("active");
    event.currentTarget.classList.add("active");
}

// Get DOM elements
const urlForm = document.getElementById('url-form');
const textForm = document.getElementById('text-form');
const loader = document.getElementById('loader');
const resultsContainer = document.getElementById('results-container');
const scoreCard = document.getElementById('score-card');
const reportDetails = document.getElementById('report-details');

// Handle URL Form Submission
urlForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const urlInput = document.getElementById('url-input').value;
    const payload = { type: 'url', url_input: urlInput };
    await performAnalysis(payload);
});

// Handle Text Form Submission
textForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const textInput = document.getElementById('text-input').value;
    const payload = { type: 'text', text_input: textInput };
    await performAnalysis(payload);
});

// Main analysis function
async function performAnalysis(payload) {
    // Show loader and hide previous results
    loader.classList.remove('hidden');
    resultsContainer.classList.add('hidden');
    
    try {
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'An unknown error occurred.');
        }

        const data = await response.json();
        displayResults(data);

    } catch (error) {
        displayError(error.message);
    } finally {
        // Hide loader
        loader.classList.add('hidden');
    }
}

// Function to display results
function displayResults(data) {
    // Determine risk level and classes
    let level, scoreClass;
    if (data.score > 75) {
        level = "High Risk / Likely Phishing";
        scoreClass = "score-high";
    } else if (data.score > 40) {
        level = "Suspicious";
        scoreClass = "score-medium";
    } else {
        level = "Likely Safe";
        scoreClass = "score-low";
    }

    // Update score card
    scoreCard.className = '';
    scoreCard.classList.add(scoreClass);
    scoreCard.innerHTML = `Overall Risk Score: ${data.score}/100 <br><small>${level}</small>`;

    // Update report details
    let reportHTML = '<ul>';
    data.report.forEach(item => {
        reportHTML += `<li>${item.replace(/`([^`]+)`/g, '<code>$1</code>')}</li>`;
    });
    reportHTML += '</ul>';
    reportDetails.innerHTML = reportHTML;

    // Show results
    resultsContainer.classList.remove('hidden');
}

// Function to display errors
function displayError(errorMessage) {
    scoreCard.className = '';
    scoreCard.classList.add('score-high');
    scoreCard.innerHTML = `Error: ${errorMessage}`;
    reportDetails.innerHTML = '';
    resultsContainer.classList.remove('hidden');
}