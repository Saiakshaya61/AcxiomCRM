/* ========================================================
   AcxiomCRM - Main JavaScript
   Simple, Beginner-Friendly Functions
   ======================================================== */

// Wait for the HTML document to fully load before running scripts
document.addEventListener('DOMContentLoaded', function () {

    // 1. Mobile Sidebar Toggle
    const toggleButton = document.getElementById('sidebarToggle');
    const sidebar = document.querySelector('.sidebar');

    if (toggleButton && sidebar) {
        toggleButton.addEventListener('click', function () {
            sidebar.classList.toggle('open');
        });
    }

    // 2. Automatically fade out flash alerts after 4 seconds
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

    // 3. Highlight current active link in sidebar based on current URL
    const currentPath = window.location.pathname;
    const menuLinks = document.querySelectorAll('.sidebar-menu a');

    menuLinks.forEach(function (link) {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });

});

// Helper function for delete confirmations
function confirmDelete(itemName) {
    return confirm("Are you sure you want to delete this " + itemName + "? This action cannot be undone.");
}

