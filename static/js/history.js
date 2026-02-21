function saveScanToHistory(scan) {
    let history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];
    history.unshift(scan); // newest first
    history = history.slice(0, 10); // limit to 10
    sessionStorage.setItem("scanHistory", JSON.stringify(history));
}

function loadScanHistory() {
    const history = JSON.parse(sessionStorage.getItem("scanHistory")) || [];
    const container = document.getElementById("scan-history-list");

    if (!container) return;
    container.innerHTML = "";

    history.forEach(item => {
        const div = document.createElement("div");
        div.className = "history-item";
        div.innerHTML = `
            <img src="${item.image}" />
            <div>
                <strong>${item.label}</strong>
                <small>${item.confidence}%</small>
            </div>
        `;
        container.appendChild(div);
    });
}

document.addEventListener("DOMContentLoaded", loadScanHistory);
