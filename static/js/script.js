/* ========================================================
   AcxiomCRM - Main JavaScript Functions (script.js)
   Beginner-friendly, Clean, and Reliable
   ======================================================== */

document.addEventListener('DOMContentLoaded', function () {

    // 1. Mobile Sidebar Toggle
    const toggleButton = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.sidebar');

    if (toggleButton && sidebar) {
        toggleButton.addEventListener('click', function () {
            sidebar.classList.toggle('open');
        });
    }

    // 2. Auto-fade flash notification banners after 4 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            alert.style.transition = 'opacity 0.5s ease';
            alert.style.opacity = '0';
            setTimeout(function () {
                alert.remove();
            }, 500);
        }, 4000);
    });

    // 3. Highlight current active menu link
    const currentPath = window.location.pathname;
    const menuLinks = document.querySelectorAll('.sidebar-menu a');
    menuLinks.forEach(function (link) {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

    // 4. Close modals when clicking backdrop
    const modals = document.querySelectorAll('.modal-overlay');
    modals.forEach(function (modal) {
        modal.addEventListener('click', function (e) {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });

});

// Modal Helper Functions
function openModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('active');
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('active');
    }
}

// Delete Confirmation
function confirmDelete(entityName) {
    return confirm("Are you sure you want to delete this " + entityName + "? This action cannot be undone.");
}

// Convert Lead Confirmation
function confirmConvertLead(leadName) {
    return confirm("Are you sure you want to convert lead '" + leadName + "' into a permanent Customer?");
}

// Client-side Stage -> Probability sync helper for Opportunity forms
function updateProbabilityFromStage(stageSelectId, probInputId) {
    const stageSelect = document.getElementById(stageSelectId);
    const probInput = document.getElementById(probInputId);
    if (!stageSelect || !probInput) return;

    const stage = stageSelect.value;
    const stageProbMap = {
        'Qualification': 20,
        'Proposal': 50,
        'Negotiation': 75,
        'Won': 100,
        'Lost': 0
    };

    if (stage in stageProbMap) {
        probInput.value = stageProbMap[stage];
    }
}

// Client-side Email and Phone Validation Helpers
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

function validatePhone(phone) {
    // Allows 7-15 digits, spaces, parentheses, dashes, plus sign
    const re = /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}$/;
    return re.test(String(phone).trim());
}

