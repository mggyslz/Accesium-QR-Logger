
document.addEventListener("DOMContentLoaded", function () {
    console.log("CSRF Debug Info:");
    const csrfInput = document.querySelector('input[name="csrf_token"]');
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');

    if (csrfInput) {
        console.log(
            "CSRF Token input found:",
            csrfInput.value
                ? "Yes (length: " + csrfInput.value.length + ")"
                : "No value"
        );
    } else {
        console.log("CSRF Token input field not found");
    }

    if (csrfMeta) {
        console.log(
            "CSRF Meta tag found:",
            csrfMeta.getAttribute("content") ? "Yes" : "No content"
        );
    } else {
        console.log("CSRF Meta tag not found");
    }
});