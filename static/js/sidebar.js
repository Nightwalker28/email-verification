$(document).ready(function() {
    
    $('#menu-toggle').on('click', function() {
        $('#sidebar').toggleClass('active');
        $('.main-container').toggleClass('sidebar-active');
        $(this).toggleClass('active');
    });

    
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

    
    $(window).on('resize', function() {
        const windowWidth = window.innerWidth;
        if (windowWidth > 480) {
            $('#sidebar').removeClass('active');
            $('.main-container').removeClass('sidebar-active');
            $('#menu-toggle').removeClass('active');
        }
    });
});