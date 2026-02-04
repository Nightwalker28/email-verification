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

  
document.addEventListener('DOMContentLoaded', function() {
    
    if (typeof Chart !== 'undefined') {
        createCharts();
    }
    
    
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
                        'rgba(168, 230, 207, 0.4)',   
                        'rgba(255, 165, 0, 0.4)',     
                        'rgba(255, 99, 132, 0.4)',    
                        'rgba(128, 128, 128, 0.3)'    
                    ],
                    borderColor: [
                        'rgba(0, 128, 0, 1)',         
                        'rgba(255, 140, 0, 1)',       
                        'rgba(220, 20, 60, 1)',       
                        'rgba(105, 105, 105, 1)'      
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
    
    
    function showAlert(message, type = 'success') {
        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type}`;
        alertDiv.textContent = message;
        
        document.body.appendChild(alertDiv);
        
        
        setTimeout(() => {
            alertDiv.style.opacity = '0';
            setTimeout(() => {
                document.body.removeChild(alertDiv);
            }, 300);
        }, 5000);
    }
});
  
