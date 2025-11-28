
let canResend = true;
let countdownSeconds = 0;

const codeInput = document.getElementById("code");
codeInput.addEventListener("input", function (e) {
    this.value = this.value.replace(/[^0-9]/g, "");
    if (this.value.length === 6) {
        document.getElementById("verifyForm").submit();
    }
});

async function resendCode(e) {
    e.preventDefault();
    if (!canResend) return;

    const link = document.getElementById("resendLink");
    const submitBtn = document.getElementById("submitBtn");
    canResend = false;
    link.classList.add("disabled");
    link.innerHTML = '<span class="loading-spinner"></span>Sending...';
    submitBtn.disabled = true;

    try {
        const csrfToken = document
            .querySelector('meta[name="csrf-token"]')
            ?.getAttribute("content");
        const res = await fetch('{{ url_for("user.resend_code") }}', {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrfToken,
            },
        });
        const data = await res.json();

        if (data.status === "success") {
            showMessage(
                "Code resent successfully. Check your email.",
                "success"
            );
            startCountdown(60);
        } else {
            showMessage(data.message || "Failed to resend code.", "danger");
            resetResendLink(link);
        }
    } catch (err) {
        showMessage("Error: " + err.message, "danger");
        resetResendLink(link);
    } finally {
        submitBtn.disabled = false;
    }
}

function startCountdown(seconds) {
    const link = document.getElementById("resendLink");
    const countdownDiv = document.getElementById("countdown");
    countdownSeconds = seconds;

    const interval = setInterval(() => {
        countdownSeconds--;
        countdownDiv.textContent = `You can resend in ${countdownSeconds} seconds`;
        if (countdownSeconds <= 0) {
            clearInterval(interval);
            canResend = true;
            link.classList.remove("disabled");
            link.textContent = "Didn't receive the code? Resend";
            countdownDiv.textContent = "";
        }
    }, 1000);
}

function resetResendLink(link) {
    canResend = true;
    link.classList.remove("disabled");
    link.textContent = "Didn't receive the code? Resend";
}

function showMessage(message, type) {
    const flashDiv = document.createElement("div");
    flashDiv.className = `flash ${type}`;
    flashDiv.textContent = message;
    const form = document.getElementById("verifyForm");
    form.parentNode.insertBefore(flashDiv, form);
    setTimeout(() => flashDiv.remove(), 5000);
}

codeInput.addEventListener("paste", function (e) {
    e.preventDefault();
    const paste = (e.clipboardData || window.clipboardData).getData("text");
    const cleaned = paste.replace(/[^0-9]/g, "").slice(0, 6);
    this.value = cleaned;
    if (cleaned.length === 6) {
        document.getElementById("verifyForm").submit();
    }
});