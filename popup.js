document.addEventListener('DOMContentLoaded', function() {
    // Fetch scan results from chrome storage
    chrome.storage.local.get(['scanResult', 'resourceScans'], function(data) {
        if (chrome.runtime.lastError) {
            console.error("Error retrieving data from storage:", chrome.runtime.lastError);
            displayMessage('Error retrieving scan results. Please try again.');
            return;
        }

        console.log("Retrieved data:", data); // Log the retrieved data for debugging

        // Check and display scan results
        if (data.scanResult) {
            displayResults(data.scanResult);
        } else {
            displayMessage('No scan results available');
        }

        // Check and display resource scans
        if (data.resourceScans) {
            displayResourceResults(data.resourceScans);
        }
    });
});

function displayResults(scanResult) {
    const resultDiv = document.getElementById('result');
    const vtData = scanResult.data;

    console.log("Scan Result Data:", vtData); // Log the scan result data for debugging

    // Check if the scan has been performed
    if (vtData.response_code === 0) {
        resultDiv.innerHTML = `
            <div class="status warning">
                This URL hasn't been scanned yet.
            </div>
        `;
        return;
    }

    const positives = vtData.positives;
    const total = vtData.total;

    // Determine the status class and message based on positives
    let statusClass = 'safe';
    let message = 'This site appears to be safe.';

    if (positives > 0) {
        statusClass = positives > 2 ? 'danger' : 'warning';
        message = `Warning: ${positives} out of ${total} security vendors flagged this site as malicious.`;
    }

    // Update the resultDiv with the scan results
    resultDiv.innerHTML = `
        <div class="status ${statusClass}">
            ${message}
        </div>
        <div>
            <p>Scanned URL: ${scanResult.url}</p>
        </div>
    `;
}

function displayResourceResults(resourceScans) {
    const resourcesDiv = document.getElementById('resources');
    resourcesDiv.innerHTML = '';

    // Iterate over resource scans and display results
    for (const [url, result] of Object.entries(resourceScans)) {
        const vtData = result.data;
        const positives = vtData.positives;
        const total = vtData.total;

        // Determine the status class and message for each resource
        let statusClass = 'safe';
        let message = 'This resource appears to be safe.';

        if (positives > 0) {
            statusClass = positives > 2 ? 'danger' : 'warning';
            message = `Warning: ${positives} out of ${total} security vendors flagged this resource as malicious.`;
        }

        // Append the resource scan results to the resourcesDiv
        resourcesDiv.innerHTML += `
            <div class="status ${statusClass}">
                ${message}
                <p>Resource URL: ${url}</p>
            </div>
        `;
    }
}

function displayMessage(message) {
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = `
        <div class="status warning">
            ${message}
        </div>
    `;
}