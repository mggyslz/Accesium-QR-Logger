

function getCSRFToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    return metaTag ? metaTag.getAttribute("content") : "";
}

const video = document.getElementById("preview");
const result = document.getElementById("result");
let lastDetected = "";
let isProcessing = false;
let resetTimeout = null;
let csrfToken = "";


navigator.mediaDevices
    .getUserMedia({ video: { facingMode: "environment" } })
    .then((stream) => {
        video.srcObject = stream;
        result.textContent = "Ready to scan";

        
        csrfToken = getCSRFToken();
        console.log("CSRF Token:", csrfToken ? "Found" : "Not found");

        requestAnimationFrame(tick);
        
        updateStats();
        
        setInterval(updateStats, 3000);
    })
    .catch((err) => {
        result.textContent = "Camera access denied: " + err;
        result.className = "error";
        console.error("Camera error:", err);
    });

const canvas = document.createElement("canvas");
const ctx = canvas.getContext("2d");

async function tick() {
    if (video.readyState === video.HAVE_ENOUGH_DATA && !isProcessing) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const qr = jsQR(imageData.data, imageData.width, imageData.height);

        if (qr && qr.data !== lastDetected) {
            lastDetected = qr.data;
            isProcessing = true;
            result.textContent = "Processing QR...";
            await processQR(qr.data);
        }
    }
    requestAnimationFrame(tick);
}

function resetScanner(delay = 3000) {
    clearTimeout(resetTimeout);
    resetTimeout = setTimeout(() => {
        lastDetected = "";
        isProcessing = false;
        result.textContent = "Ready to scan";
        result.className = "";
    }, delay);
}

async function processQR(data, pin = null) {
    try {
        const payload = { qr_data: data, pin };

        
        if (csrfToken) {
            payload.csrf_token = csrfToken;
        }

        const headers = { "Content-Type": "application/json" };
        if (csrfToken) {
            headers["X-CSRFToken"] = csrfToken;
        }

        const res = await fetch("/scanner/process", {
            method: "POST",
            headers: headers,
            body: JSON.stringify(payload),
        });
        const json = await res.json();

        if (json.status === "require_pin") {
            const userPin = prompt(json.message);
            if (userPin) {
                await processQR(data, userPin);
            } else {
                result.textContent = "PIN entry canceled";
                result.className = "error";
                resetScanner(2000);
            }
        } else if (json.status === "success") {
            result.textContent = `${json.name} → ${json.action} (${json.location})`;
            result.className = "success";
            playBeep(json.action === "IN" ? 800 : 600);
            updateStats();
            resetScanner(3000);
        } else {
            result.textContent = json.message;
            result.className = "error";
            playBeep(300);
            resetScanner(2000);
        }
    } catch (err) {
        result.textContent = "Connection error: " + err.message;
        result.className = "error";
        resetScanner(2000);
    }
}

function playBeep(frequency, duration = 150) {
    try {
        const audioCtx = new (window.AudioContext ||
            window.webkitAudioContext)();
        const oscillator = audioCtx.createOscillator();
        const gainNode = audioCtx.createGain();
        oscillator.connect(gainNode);
        gainNode.connect(audioCtx.destination);
        oscillator.frequency.value = frequency;
        oscillator.type = "sine";
        gainNode.gain.setValueAtTime(0.3, audioCtx.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(
            0.01,
            audioCtx.currentTime + duration / 1000
        );
        oscillator.start(audioCtx.currentTime);
        oscillator.stop(audioCtx.currentTime + duration / 1000);
    } catch (e) {
        console.log("Audio not supported");
    }
}

async function updateStats() {
    try {
        // Add timestamp to prevent caching
        const res = await fetch(`/scanner/stats?t=${Date.now()}`);
        const json = await res.json();
        if (json.status === "success") {
            const insideEl = document.getElementById("totalInside");
            const scansEl = document.getElementById("todayScans");
            
            if (insideEl) {
                insideEl.textContent = json.total_inside || 0;
                console.log("Updated totalInside:", json.total_inside);
            }
            if (scansEl) {
                scansEl.textContent = json.today_scans || 0;
                console.log("Updated todayScans:", json.today_scans);
            }
        } else {
            console.error("Stats update failed:", json);
        }
    } catch (err) {
        console.error("Failed to update stats:", err);
    }
}
