$(document).ready(function() {
    // Add menu toggle button for mobile view if it doesn't exist
    if ($('.menu-toggle').length === 0) {
        const menuToggle = `
            <button class="menu-toggle" id="menu-toggle">
                <span></span>
                <span></span>
                <span></span>
            </button>
        `;
        $('body').prepend(menuToggle);
    }

    // Toggle sidebar on mobile
    $('#menu-toggle').on('click', function() {
        $('#sidebar').toggleClass('active');
        $('.main-container').toggleClass('sidebar-active');
        $(this).toggleClass('active');
    });

    // Close sidebar when clicking outside on mobile
    $(document).on('click', function(e) {
        const windowWidth = window.innerWidth;
        if (windowWidth <= 480) {
            if (!$(e.target).closest('#sidebar').length && 
                !$(e.target).closest('#menu-toggle').length && 
                $('#sidebar').hasClass('active')) {
                $('#sidebar').removeClass('active');
                $('.main-container').removeClass('sidebar-active');
                $('#menu-toggle').removeClass('active');
            }
        }
    });

    // Handle window resize
    $(window).on('resize', function() {
        const windowWidth = window.innerWidth;
        if (windowWidth > 480) {
            $('#sidebar').removeClass('active');
            $('.main-container').removeClass('sidebar-active');
            $('#menu-toggle').removeClass('active');
        }
    });
});