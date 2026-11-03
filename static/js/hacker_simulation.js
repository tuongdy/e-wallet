
const connectionButton = document.getElementById("check-connection");
const connectionMessage = document.getElementById("connection-message");

const serverStatus = document.getElementById("server-status");
const serverDot = document.getElementById("server-dot");
const hackerStatus = document.getElementById("hacker-status");
const networkStatus = document.getElementById("network-status");

const labLog = document.getElementById("lab-log");
const clearLogButton = document.getElementById("clear-lab-log");

function addLog(message, type = "info") {
    const emptyLog = labLog.querySelector(".empty-log");

    if (emptyLog) {
        emptyLog.remove();
    }

    const entry = document.createElement("p");
    const time = new Date().toLocaleTimeString("vi-VN");

    entry.textContent = `[${time}] ${message}`;
    entry.dataset.type = type;

    labLog.prepend(entry);
}

function setServerStatus(online) {
    serverStatus.textContent = online ? "Đang hoạt động" : "Không kết nối";

    serverDot.classList.toggle("online", online);

    hackerStatus.textContent = online
        ? "Đã kết nối tới môi trường kiểm thử"
        : "Chưa kết nối";

    networkStatus.textContent = online
        ? "Server phản hồi"
        : "Không có phản hồi";
}

async function checkConnection() {
    connectionButton.disabled = true;
    connectionButton.textContent = "Đang kiểm tra...";

    try {
        const response = await fetch("/api/health", {
            method: "GET",
            credentials: "same-origin",
            headers: {
                "Accept": "application/json"
            }
        });

        if (response.redirected) {
            throw new Error("Phiên đăng nhập không hợp lệ.");
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const result = await response.json();

        if (!result) {
            throw new Error("Phản hồi máy chủ không hợp lệ.");
        }

        setServerStatus(true);

        connectionMessage.textContent =
            "Kết nối tới TRUEWALLET Server thành công. Máy chủ đã phản hồi.";

        addLog("Kiểm tra kết nối: Server phản hồi thành công.", "success");

    } catch (error) {
        setServerStatus(false);

        connectionMessage.textContent =
            "Không thể kết nối: " + error.message;

        addLog("Kiểm tra kết nối thất bại: " + error.message, "error");

    } finally {
        connectionButton.disabled = false;
        connectionButton.textContent = "Kiểm tra kết nối";
    }
}

connectionButton.addEventListener("click", checkConnection);

clearLogButton.addEventListener("click", () => {
    labLog.innerHTML = '<p class="empty-log">Chưa có sự kiện kiểm thử.</p>';
});

const scenarioEndpoints = {
    inspection: {
        name: "Encrypted Data Inspection",
        endpoint: "/api/simulation/package",
        method: "POST",
        body: {}
    },

    integrity: {
        name: "Data Integrity Check",
        endpoint: "/api/simulation/tampering",
        method: "POST",
        body: {}
    },

    replay: {
        name: "Replay Protection",
        endpoint: "/api/simulation/replay",
        method: "POST",
        body: {}
    },

    hybrid: {
        name: "Hybrid Encryption",
        endpoint: "/api/simulation/hybrid",
        method: "POST",
        body: {}
    }
};

async function runLabScenario(scenarioId, button) {
    const scenario = scenarioEndpoints[scenarioId];

    if (!scenario) {
        addLog("Kịch bản không hợp lệ.", "error");
        return;
    }

    button.disabled = true;
    button.textContent = "Đang kiểm thử...";

    addLog(`Bắt đầu kiểm thử: ${scenario.name}`);

    try {
        const response = await fetch(scenario.endpoint, {
            method: scenario.method,
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            body: JSON.stringify(scenario.body)
        });

        if (response.redirected) {
            throw new Error("Phiên đăng nhập đã hết hạn.");
        }

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.message || `Máy chủ trả về HTTP ${response.status}`
            );
        }

        const passed = result.success === true ||
            result.status === "success";

        addLog(
            `${scenario.name}: ${passed ? "Đã nhận phản hồi thành công" : "Đã nhận kết quả kiểm thử"}.`,
            passed ? "success" : "info"
        );

        addLog(
            "Phản hồi: " + JSON.stringify(result),
            "info"
        );

    } catch (error) {
        addLog(
            `${scenario.name}: ${error.message}`,
            "error"
        );

    } finally {
        button.disabled = false;
        button.textContent = getOriginalButtonText(scenarioId);
    }
}

function getOriginalButtonText(scenarioId) {
    const labels = {
        inspection: "Kiểm tra dữ liệu",
        integrity: "Kiểm tra toàn vẹn",
        replay: "Kiểm tra chống gửi lại",
        hybrid: "Kiểm tra AES + RSA"
    };

    return labels[scenarioId] || "Chạy kiểm thử";
}

document.querySelectorAll(".lab-action").forEach(button => {
    button.addEventListener("click", () => {
        runLabScenario(button.dataset.scenario, button);
    });
});

// Trạng thái ban đầu
setServerStatus(false);
addLog("Hacker Simulation Lab đã khởi tạo.", "info");
