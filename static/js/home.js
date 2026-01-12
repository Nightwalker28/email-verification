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
    // const manualEmailForm = document.getElementById('manualEmailForm');
    // if (manualEmailForm) {
    //     manualEmailForm.addEventListener('submit', function(event) {
    //         event.preventDefault();
            
    //         const emailInput = document.getElementById('emailAddress');
    //         const email = emailInput.value.trim();
            
    //         if (email) {
    //             // Show loading state
    //             const submitButton = manualEmailForm.querySelector('button[type="submit"]');
    //             const originalText = submitButton.textContent;
    //             submitButton.disabled = true;
    //             submitButton.textContent = 'Verifying...';
                
    //             // Send the verification request
    //             fetch('/api/verify', {
    //                 method: 'POST',
    //                 headers: {
    //                     'Content-Type': 'application/json',
    //                 },
    //                 body: JSON.stringify({ email }),
    //             })
    //             .then(response => response.json())
    //             .then(data => {
    //                 // Reset form and button
    //                 submitButton.disabled = false;
    //                 submitButton.textContent = originalText;
                    
    //                 if (data.success) {
    //                     // Redirect to the result page or reload to show updated results
    //                     window.location.reload();
    //                 } else {
    //                     // Show error
    //                     showAlert(data.message || 'Verification failed', 'error');
    //                 }
    //             })
    //             .catch(error => {
    //                 submitButton.disabled = false;
    //                 submitButton.textContent = originalText;
    //                 showAlert('An error occurred during verification', 'error');
    //                 console.error('Error:', error);
    //             });
    //         }
    //     });
    // }
    
    // Function to create charts
    function createCharts() {
        createRecentChart();
        createListChart();
    }
    

    function createRecentChart() {
        const recentChartCanvas = document.getElementById('recent-chart');
        if (!recentChartCanvas) return;

        const recentSummary = getRecentSummaryData();
        if (!recentSummary) return;

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
                        'rgba(168, 230, 207, 0.4)',   // light green
                        'rgba(255, 165, 0, 0.4)',     // light orange
                        'rgba(255, 99, 132, 0.4)',    // light red
                        'rgba(128, 128, 128, 0.3)'    // light gray
                    ],
                    borderColor: [
                        'rgba(0, 128, 0, 1)',         // dark green
                        'rgba(255, 140, 0, 1)',       // dark orange
                        'rgba(220, 20, 60, 1)',       // dark red
                        'rgba(105, 105, 105, 1)'      // dark gray
                    ],
                    borderWidth: 2,
                    borderRadius: 3,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: false
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

    
    function createListChart() {
        const listChartCanvas = document.getElementById('list-chart');
        if (!listChartCanvas) return;
        
        const listSummary = getListSummaryData();
        if (!listSummary) return;
        
        // Create radar chart with pastel colors
        new Chart(listChartCanvas, {
            type: 'radar',
            data: {
                labels: ['Verified', 'Risky', 'Invalid', 'Unknown'],
                datasets: [{
                    label: 'Email Status',
                    data: [
                        listSummary.total_verified,
                        listSummary.total_risky,
                        listSummary.total_invalid,
                        listSummary.total_unknown
                    ],
                    backgroundColor: 'rgba(168, 230, 207, 0.4)', 
                    borderColor: 'rgba(0, 128, 0, 1)',
                    borderWidth: 2,
                    pointBackgroundColor: 'rgba(0, 128, 0, 1)',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: '#a8e6cf'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: false,
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        ticks: {
                            display: false,
                            stepSize: Math.max(1, Math.ceil(Math.max(
                                listSummary.total_verified,
                                listSummary.total_risky,
                                listSummary.total_invalid,
                                listSummary.total_unknown
                            ) / 5))
                        },
                        pointLabels: {
                            font: {
                                size: 12
                            }
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
  