// pricing.js - Centralized pricing configuration

const PRICING_CONFIG = {
    // Main pricing variables - Update these to change all pricing
    yearlyDiscount: 0.20,  // 20% discount for yearly billing
    plans: {
        professional: {
            monthly: 49
        },
        enterprise: {
            monthly: 169
        }
    }
};

// Calculate derived pricing values
function calculatePricing() {
    const config = PRICING_CONFIG;
    
    return {
        discount: {
            percentage: Math.round(config.yearlyDiscount * 100),
            multiplier: 1 - config.yearlyDiscount
        },
        professional: {
            monthly: config.plans.professional.monthly,
            yearly: Math.floor(config.plans.professional.monthly * (1 - config.yearlyDiscount)),
            yearlyTotal: Math.floor(config.plans.professional.monthly * (1 - config.yearlyDiscount)) * 12
        },
        enterprise: {
            monthly: config.plans.enterprise.monthly,
            yearly: Math.floor(config.plans.enterprise.monthly * (1 - config.yearlyDiscount)),
            yearlyTotal: Math.floor(config.plans.enterprise.monthly * (1 - config.yearlyDiscount)) * 12
        }
    };
}

// Initialize pricing on page load
function initializePricing() {
    const pricing = calculatePricing();
    
    // Update discount badge
    const discountBadge = document.querySelector('.save-badge');
    if (discountBadge) {
        discountBadge.textContent = `Save ${pricing.discount.percentage}%`;
    }
    
    // Update Professional plan pricing
    updatePlanPricing('professional', pricing.professional);
    
    // Update Enterprise plan pricing
    updatePlanPricing('enterprise', pricing.enterprise);
}

// Update pricing for a specific plan
function updatePlanPricing(planName, planPricing) {
    const planCard = document.querySelector(`[data-plan="${planName}"]`);
    if (!planCard) return;
    
    // Update monthly price
    const monthlyPrice = planCard.querySelector('.monthly-price');
    if (monthlyPrice) {
        monthlyPrice.textContent = planPricing.monthly;
    }
    
    // Update yearly price
    const yearlyPrice = planCard.querySelector('.yearly-price');
    if (yearlyPrice) {
        yearlyPrice.textContent = planPricing.yearly;
    }
    
    // Update yearly total in note
    const yearlyNote = planCard.querySelector('.yearly-note');
    if (yearlyNote) {
        yearlyNote.innerHTML = `Billed yearly ($${planPricing.yearlyTotal.toLocaleString()}/year)`;
    }
}

// Handle billing toggle functionality
function initializeBillingToggle() {
    const billingToggle = document.getElementById('billing-toggle');
    const monthlyPrices = document.querySelectorAll('.monthly-price');
    const yearlyPrices = document.querySelectorAll('.yearly-price');
    const monthlyNotes = document.querySelectorAll('.monthly-note');
    const yearlyNotes = document.querySelectorAll('.yearly-note');

    if (!billingToggle) return;

    billingToggle.addEventListener('change', function() {
        if (this.checked) {
            // Show yearly prices
            monthlyPrices.forEach(el => el.style.display = 'none');
            yearlyPrices.forEach(el => el.style.display = 'inline');
            monthlyNotes.forEach(el => el.style.display = 'none');
            yearlyNotes.forEach(el => el.style.display = 'block');
        } else {
            // Show monthly prices
            monthlyPrices.forEach(el => el.style.display = 'inline');
            yearlyPrices.forEach(el => el.style.display = 'none');
            monthlyNotes.forEach(el => el.style.display = 'block');
            yearlyNotes.forEach(el => el.style.display = 'none');
        }
    });
}

// Initialize everything when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    initializePricing();
    initializeBillingToggle();
});

// Export for use in other files if needed (ES6 modules)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { PRICING_CONFIG, calculatePricing };
}