

$(document).ready(function() {
    $(".menu-button").click(function() {
        $(".dropdown").toggle();
    });

    $(document).click(function(event) {
        if (!$(event.target).closest('.menu').length) {
            $(".dropdown").hide();
        }
    });
});

