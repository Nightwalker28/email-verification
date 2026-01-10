$(document).ready(() => {
    $('a[href="/list"]').on('click', function (event) {
      event.preventDefault();
      $('#loadingOverlay').show();
      $.ajax({
        url: '/list',
        type: 'GET',
        success: () => window.location.href = '/list',
        error: (xhr) => {
          $('#loadingOverlay').hide();
          const errorMessage = xhr.responseJSON ? xhr.responseJSON.error : "An error occurred";
          displayMessage(errorMessage, true);
        }
      });
    });
  });

  // Initialize the dashboard charts
document.addEventListener('DOMContentLoaded', function() {
    // Create charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        createCharts();
    }
    
    // Handle quick email verification form submission
    const manualEmailForm = document.getElementById('manualEmailForm');
    if (manualEmailForm) {
        manualEmailForm.addEventListener('submit', function(event) {
            event.preventDefault();
            
            const emailInput = document.getElementById('emailAddress');
            const email = emailInput.value.trim();
            
            if (email) {
                // Show loading state
                const submitButton = manualEmailForm.querySelector('button[type="submit"]');
                const originalText = submitButton.textContent;
                submitButton.disabled = true;
                submitButton.textContent = 'Verifying...';
                
                // Send the verification request
                fetch('/api/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ email }),
                })
                .then(response => response.json())
                .then(data => {
                    // Reset form and button
                    submitButton.disabled = false;
                    submitButton.textContent = originalText;
                    
                    if (data.success) {
                        // Redirect to the result page or reload to show updated results
                        window.location.reload();
                    } else {
                        // Show error
                        showAlert(data.message || 'Verification failed', 'error');
                    }
                })
                .catch(error => {
                    submitButton.disabled = false;
                    submitButton.textContent = originalText;
                    showAlert('An error occurred during verification', 'error');
                    console.error('Error:', error);
                });
            }
        });
    }
    
    // Function to create charts
    function createCharts() {
        createRecentChart();
        createListChart();
    }
    
    // Create recent verification chart
    function createRecentChart() {
        const recentChartCanvas = document.getElementById('recent-chart');
        if (!recentChartCanvas) return;
        
        const recentSummary = getRecentSummaryData();
        if (!recentSummary) return;
        
        // Create bar chart
        new Chart(recentChartCanvas, {
            type: 'bar',
            data: {
                labels: ['Verified', 'Risky', 'Invalid', 'Unknown'],
                datasets: [{
                    label: 'Emails',
                    data: [
                        recentSummary.recent_verified,
                        recentSummary.recent_risky,
                        recentSummary.recent_invalid,
                        recentSummary.recent_unknown
                    ],
                    backgroundColor: [
                        '#4CAF50',  // Green for verified
                        '#f39c12',  // Orange for risky
                        '#e74c3c',  // Red for invalid
                        '#95a5a6'   // Gray for unknown
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Last 30 Days Results',
                        font: {
                            size: 14
                        }
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
    }
    
    // Create list summary chart
    function createListChart() {
        const listChartCanvas = document.getElementById('list-chart');
        if (!listChartCanvas) return;
        
        const listSummary = getListSummaryData();
        if (!listSummary) return;
        
        // Create pie chart
        new Chart(listChartCanvas, {
            type: 'pie',
            data: {
                labels: ['Verified', 'Risky', 'Invalid', 'Unknown'],
                datasets: [{
                    data: [
                        listSummary.total_verified,
                        listSummary.total_risky,
                        listSummary.total_invalid,
                        listSummary.total_unknown
                    ],
                    backgroundColor: [
                        '#4CAF50',  // Green for verified
                        '#f39c12',  // Orange for risky
                        '#e74c3c',  // Red for invalid
                        '#95a5a6'   // Gray for unknown
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Overall Lists Results',
                        font: {
                            size: 14
                        }
                    }
                }
            }
        });
    }
    
    // Get recent summary data from hidden element
    function getRecentSummaryData() {
        const recentSummaryElement = document.getElementById('recent-summary-data');
        if (recentSummaryElement) {
            try {
                return JSON.parse(recentSummaryElement.getAttribute('data-summary'));
            } catch (e) {
                console.error('Error parsing recent summary data:', e);
            }
        }
        return null;
    }
    
    // Get list summary data from hidden element
    function getListSummaryData() {
        const listSummaryElement = document.getElementById('list-summary-data');
        if (listSummaryElement) {
            try {
                return JSON.parse(listSummaryElement.getAttribute('data-summary'));
            } catch (e) {
                console.error('Error parsing list summary data:', e);
            }
        }
        return null;
    }
    
    // Function to show alerts
    function showAlert(message, type = 'success') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;
        
        document.body.appendChild(alertDiv);
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            alertDiv.style.opacity = '0';
            setTimeout(() => {
                document.body.removeChild(alertDiv);
            }, 300);
        }, 5000);
    }
});
  