const connectionButton = document.getElementById("check-connection");
const connectionMessage = document.getElementById("connection-message");

const serverStatus = document.getElementById("server-status");
const serverDot = document.getElementById("server-dot");
const hackerStatus = document.getElementById("hacker-status");
const networkStatus = document.getElementById("network-status");

const labLog = document.getElementById("lab-log");
const clearLogButton = document.getElementById("clear-lab-log");
// LIVE SECURITY MONITORING
const refreshMonitoringButton = document.getElementById("refresh-monitoring");

const monitorServerStatus = document.getElementById("monitor-server-status");
const monitorDatabaseStatus = document.getElementById("monitor-database-status");
const monitorEncryptionStatus = document.getElementById("monitor-encryption-status");

const monitorTotalEvents = document.getElementById("monitor-total-events");
const monitorBlockedEvents = document.getElementById("monitor-blocked-events");
const monitorSuccessEvents = document.getElementById("monitor-success-events");

const monitoringEventsList = document.getElementById("monitoring-events-list");
const monitoringLastUpdate = document.getElementById("monitoring-last-update");

// Lưu gói giao dịch giả lập hiện tại
let currentLabPackage = null;

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

// Gửi yêu cầu tới Flask API
async function postJson(endpoint, data = {}) {
    const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        body: JSON.stringify(data)
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

    return result;
}

// Tạo gói giao dịch giả lập
async function createLabPackage() {
    const result = await postJson("/api/simulation/package");

    if (
        result.success !== true ||
        !result.transaction ||
        !result.encrypted_transaction
    ) {
        throw new Error(
            result.message || "Không thể tạo gói giao dịch giả lập."
        );
    }

    currentLabPackage = {
        transaction: result.transaction,
        encrypted_transaction: result.encrypted_transaction
    };

    addLog(
        `Đã tạo giao dịch giả lập ${result.transaction.transaction_id}.`,
        "success"
    );

    return currentLabPackage;
}

// Lấy gói hiện tại, nếu chưa có thì tạo mới
async function getLabPackage() {
    if (!currentLabPackage) {
        addLog("Chưa có gói dữ liệu. Đang tạo giao dịch giả lập...");
        await createLabPackage();
    }

    return currentLabPackage;
}

// Kiểm tra kết nối máy chủ
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

// Xóa nhật ký
clearLogButton.addEventListener("click", () => {
    labLog.innerHTML = '<p class="empty-log">Chưa có sự kiện kiểm thử.</p>';
});

// Nội dung các kịch bản kiểm thử
const scenarioEndpoints = {
    inspection: {
        name: "Encrypted Data Inspection"
    },

    integrity: {
        name: "Data Integrity Check"
    },

    replay: {
        name: "Replay Protection"
    },

    hybrid: {
        name: "Hybrid Encryption"
    }
};

// Chạy kịch bản kiểm thử
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
        let result;

        // 01. INSPECTION
        if (scenarioId === "inspection") {
            const packageData = await createLabPackage();

            result = {
                success: true,
                transaction_id:
                    packageData.transaction.transaction_id,
                key_id:
                    packageData.encrypted_transaction.key_id,
                message: "Đã tạo gói giao dịch và mã hóa thành công."
            };

            addLog(
                `Gói mã hóa đã sẵn sàng. Transaction ID: ${result.transaction_id}`,
                "success"
            );

            addLog(
                `Key ID: ${result.key_id || "Không có thông tin"}`,
                "info"
            );
        }

        // Các kịch bản còn lại cần gói giao dịch
        else {
            const packageData = await getLabPackage();

            // 02. INTEGRITY
            if (scenarioId === "integrity") {
                result = await postJson(
                    "/api/simulation/tampering",
                    {
                        encrypted_transaction:
                            packageData.encrypted_transaction
                    }
                );

                if (result.success && result.rejected === true) {
                    addLog(
                        "AES-GCM đã phát hiện dữ liệu thay đổi và từ chối giải mã.",
                        "success"
                    );
                } else {
                    addLog(
                        "Cảnh báo: dữ liệu thay đổi chưa bị từ chối.",
                        "error"
                    );
                }
            }

            // 03. REPLAY
            else if (scenarioId === "replay") {
                result = await postJson(
                    "/api/simulation/replay",
                    {
                        encrypted_transaction:
                            packageData.encrypted_transaction
                    }
                );

                if (
                    result.success &&
                    result.first_request_accepted === true &&
                    result.replay_rejected === true
                ) {
                    addLog(
                        "Giao dịch đầu tiên được chấp nhận. Lần gửi lại bị từ chối.",
                        "success"
                    );
                } else {
                    addLog(
                        "Cảnh báo: hệ thống chưa từ chối được giao dịch gửi lại.",
                        "error"
                    );
                }
            }

            // 04. HYBRID ENCRYPTION
            else if (scenarioId === "hybrid") {
                result = await postJson(
                    "/api/simulation/hybrid",
                    {
                        transaction: packageData.transaction,
                        encrypted_transaction:
                            packageData.encrypted_transaction
                    }
                );

                if (
                    result.success &&
                    result.verified === true
                ) {
                    addLog(
                        "RSA khôi phục khóa AES và AES-GCM xác thực dữ liệu thành công.",
                        "success"
                    );
                } else {
                    addLog(
                        "Xác minh thất bại: dữ liệu sau giải mã không khớp.",
                        "error"
                    );
                }
            }
        }

        if (result.message) {
            addLog("Kết quả: " + result.message, "info");
        }

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

// Tên hiển thị ban đầu của các nút
function getOriginalButtonText(scenarioId) {
    const labels = {
        inspection: "Kiểm tra dữ liệu",
        integrity: "Kiểm tra toàn vẹn",
        replay: "Kiểm tra chống gửi lại",
        hybrid: "Kiểm tra AES + RSA"
    };

    return labels[scenarioId] || "Chạy kiểm thử";
}

// Gắn sự kiện cho các nút
document.querySelectorAll(".lab-action").forEach(button => {
    button.addEventListener("click", () => {
        runLabScenario(button.dataset.scenario, button);
    });
});

// Trạng thái ban đầu
setServerStatus(false);
addLog("Hacker Simulation Lab đã khởi tạo.", "info");

// ==========================================
// LIVE SECURITY MONITORING
// ==========================================

// Lấy dữ liệu JSON từ API
async function getMonitoringData(endpoint) {
    const response = await fetch(endpoint, {
        method: "GET",
        credentials: "same-origin",
        headers: {
            "Accept": "application/json"
        }
    });

    if (response.redirected) {
        throw new Error("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.");
    }

    if (!response.ok) {
        throw new Error(`Không thể lấy dữ liệu: HTTP ${response.status}`);
    }

    return await response.json();
}


// Hiển thị trạng thái hệ thống
function updateMonitoringStatus(data) {
    if (monitorServerStatus) {
        monitorServerStatus.textContent =
            data.server === "online" ? "ONLINE" : "DEGRADED";
    }

    if (monitorDatabaseStatus) {
        monitorDatabaseStatus.textContent =
            data.database === "connected" ? "CONNECTED" : "OFFLINE";
    }

    if (monitorEncryptionStatus) {
        monitorEncryptionStatus.textContent =
            data.encryption || "Không xác định";
    }
}


// Hiển thị thống kê bảo mật
function updateMonitoringSummary(data) {
    if (!data.summary) return;

    if (monitorTotalEvents) {
        monitorTotalEvents.textContent =
            data.summary.total_events ?? 0;
    }

    if (monitorBlockedEvents) {
        monitorBlockedEvents.textContent =
            data.summary.blocked_events ?? 0;
    }

    if (monitorSuccessEvents) {
        monitorSuccessEvents.textContent =
            data.summary.successful_events ?? 0;
    }
}


// Hiển thị danh sách sự kiện
function updateMonitoringEvents(events) {
    if (!monitoringEventsList) return;

    monitoringEventsList.replaceChildren();

    if (!Array.isArray(events) || events.length === 0) {
        const emptyMessage = document.createElement("p");
        emptyMessage.className = "empty-log";
        emptyMessage.textContent = "Chưa có sự kiện bảo mật nào.";
        monitoringEventsList.appendChild(emptyMessage);
        return;
    }

    events.forEach(event => {
        const item = document.createElement("div");
        item.className = "monitor-event-item";

        const heading = document.createElement("div");
        heading.className = "monitor-event-heading";

        const eventName = document.createElement("strong");
        eventName.textContent = event.event_type || "SECURITY EVENT";

        const result = document.createElement("span");
        result.className = "monitor-event-result";
        result.textContent = event.result || "UNKNOWN";

        heading.appendChild(eventName);
        heading.appendChild(result);

        const message = document.createElement("p");
        message.textContent = event.message || "Không có mô tả.";

        const details = document.createElement("small");

        let formattedTime = "Không xác định";

        if (event.timestamp) {
            const date = new Date(event.timestamp);

            if (!Number.isNaN(date.getTime())) {
                formattedTime = date.toLocaleString("vi-VN");
            }
        }

        details.textContent =
            `${formattedTime} | ${event.method || "N/A"} ${event.endpoint || ""}`;

        item.appendChild(heading);
        item.appendChild(message);
        item.appendChild(details);

        monitoringEventsList.appendChild(item);
    });
}


// Cập nhật toàn bộ dữ liệu giám sát
let monitoringRequestInProgress = false;

async function refreshMonitoring() {
    if (monitoringRequestInProgress) return;

    monitoringRequestInProgress = true;

    try {
        const [statusData, summaryData, eventsData] = await Promise.all([
            getMonitoringData("/api/security/status"),
            getMonitoringData("/api/security/summary"),
            getMonitoringData("/api/security/events?limit=20")
        ]);

        if (!statusData.success ||
            !summaryData.success ||
            !eventsData.success) {
            throw new Error("Máy chủ trả về dữ liệu không hợp lệ.");
        }

        updateMonitoringStatus(statusData);
        updateMonitoringSummary(summaryData);
        updateMonitoringEvents(eventsData.events);

        if (monitoringLastUpdate) {
            monitoringLastUpdate.textContent =
                "Cập nhật lúc " + new Date().toLocaleTimeString("vi-VN");
        }

    } catch (error) {
        console.error("Monitoring error:", error);

        if (monitoringLastUpdate) {
            monitoringLastUpdate.textContent = error.message;
        }

    } finally {
        monitoringRequestInProgress = false;
    }
}


// Nút cập nhật thủ công
if (refreshMonitoringButton) {
    refreshMonitoringButton.addEventListener("click", refreshMonitoring);
}


// Tự động cập nhật mỗi 3 giây
refreshMonitoring();

setInterval(refreshMonitoring, 3000);


// ==========================================
// SECTION 07: INTEGRATED SECURITY ASSESSMENT
// ==========================================

const assessmentButton = document.getElementById("start-full-assessment");
const assessmentStatus = document.getElementById("assessment-status");
const assessmentProgressText = document.getElementById("assessment-progress-text");
const assessmentProgressPercent = document.getElementById("assessment-progress-percent");
const assessmentProgressFill = document.getElementById("assessment-progress-fill");

const assessmentCompleted = document.getElementById("assessment-completed");
const assessmentPassed = document.getElementById("assessment-passed");
const assessmentWarning = document.getElementById("assessment-warning");
const assessmentFailed = document.getElementById("assessment-failed");

const assessmentConsole = document.getElementById("assessment-console-output");
const assessmentConsoleStatus = document.getElementById("assessment-console-status");

const assessmentResults = document.getElementById("assessment-results");
const assessmentFinalReport = document.getElementById("assessment-final-report");
const assessmentReportContent = document.getElementById("assessment-report-content");

// Các bài kiểm thử tương ứng với 8 giai đoạn Backend
const assessmentStages = [
    {
        id: "initialize",
        name: "Initialize Scanner",
        description: "Khởi tạo bộ kiểm thử bảo mật."
    },
    {
        id: "recon",
        name: "Web Reconnaissance",
        description: "Kiểm tra HTTP response và endpoint."
    },
    {
        id: "web",
        name: "Web Security Scanning",
        description: "Kiểm tra cấu hình web, session và API."
    },
    {
        id: "aes",
        name: "AES-256-GCM Verification",
        description: "Kiểm tra quá trình mã hóa dữ liệu."
    },
    {
        id: "rsa",
        name: "RSA-OAEP Key Protection",
        description: "Kiểm tra bảo vệ và khôi phục khóa AES."
    },
    {
        id: "integrity",
        name: "Integrity & Decryption",
        description: "Kiểm tra giải mã và tính toàn vẹn."
    },
    {
        id: "e2e",
        name: "End-to-End Verification",
        description: "Đối chiếu toàn bộ giao dịch sau giải mã."
    },
    {
        id: "report",
        name: "Generate Security Report",
        description: "Tổng hợp kết quả kiểm thử."
    }
];

let assessmentRunning = false;
let assessmentResultsData = [];
let currentAssessmentId = null;


// Ghi thông tin vào Assessment Console
function assessmentConsoleLog(message, type = "info") {
    if (!assessmentConsole) return;

    const line = document.createElement("p");
    const time = new Date().toLocaleTimeString("vi-VN");

    line.textContent = `[${time}] [${type.toUpperCase()}] ${message}`;
    line.dataset.type = type;

    assessmentConsole.appendChild(line);
    assessmentConsole.scrollTop = assessmentConsole.scrollHeight;
}


// Cập nhật trạng thái một giai đoạn
function updateAssessmentStage(stageId, status, message = "") {
    const stage = document.querySelector(
        `.assessment-stage[data-stage="${stageId}"]`
    );

    if (!stage) return;

    const statusElement = stage.querySelector(".stage-status");

    if (statusElement) {
        statusElement.textContent = status;
        statusElement.dataset.status = status.toLowerCase();
    }

    if (message) {
        stage.title = message;
    }
}


// Cập nhật trạng thái các tiêu chí mật mã
function updateCryptoChecks(checks) {
    if (!checks || typeof checks !== "object") return;

    Object.entries(checks).forEach(([key, value]) => {
        const item = document.querySelector(
            `.assessment-stage[data-crypto="${key}"]`
        );

        if (!item) return;

        const statusElement = item.querySelector(".stage-status");

        if (statusElement) {
            const status = normalizeAssessmentStatus(value.status);

            statusElement.textContent = status;
            statusElement.dataset.status = status.toLowerCase();
        }
    });
}


// Chuẩn hóa trạng thái
function normalizeAssessmentStatus(status) {
    const allowed = ["PASSED", "WARNING", "FAILED"];

    const normalized = String(status || "").toUpperCase();

    return allowed.includes(normalized) ? normalized : "WARNING";
}


// Cập nhật số liệu thống kê
function updateAssessmentStatistics() {
    const completed = assessmentResultsData.length;

    const passed = assessmentResultsData.filter(
        item => item.status === "PASSED"
    ).length;

    const warning = assessmentResultsData.filter(
        item => item.status === "WARNING"
    ).length;

    const failed = assessmentResultsData.filter(
        item => item.status === "FAILED"
    ).length;

    assessmentCompleted.textContent = completed;
    assessmentPassed.textContent = passed;
    assessmentWarning.textContent = warning;
    assessmentFailed.textContent = failed;
}


// Cập nhật tiến trình
function updateAssessmentProgress(completed) {
    const percent = Math.round(
        (completed / assessmentStages.length) * 100
    );

    assessmentProgressPercent.textContent = `${percent}%`;
    assessmentProgressText.textContent =
        `${completed}/${assessmentStages.length} stages completed`;

    assessmentProgressFill.style.width = `${percent}%`;
}


// Hiển thị bằng chứng và kết quả
function renderAssessmentFinding(result) {
    if (!assessmentResults) return;

    const empty = assessmentResults.querySelector(".empty-log");

    if (empty) empty.remove();

    const card = document.createElement("div");
    card.className = "assessment-finding";
    card.dataset.status = result.status.toLowerCase();

    const heading = document.createElement("div");
    heading.className = "assessment-finding-heading";

    const name = document.createElement("strong");
    name.textContent = result.name;

    const badge = document.createElement("span");
    badge.textContent = result.status;
    badge.dataset.status = result.status.toLowerCase();

    heading.appendChild(name);
    heading.appendChild(badge);

    const message = document.createElement("p");
    message.textContent = result.message;

    card.appendChild(heading);
    card.appendChild(message);

    if (result.evidence !== undefined && result.evidence !== null) {
        const evidenceTitle = document.createElement("strong");
        evidenceTitle.textContent = "Evidence";

        const evidence = document.createElement("pre");
        evidence.textContent =
            typeof result.evidence === "string"
                ? result.evidence
                : JSON.stringify(result.evidence, null, 2);

        card.appendChild(evidenceTitle);
        card.appendChild(evidence);
    }

    assessmentResults.appendChild(card);
}


// Gọi API kiểm thử một giai đoạn
async function executeAssessmentStage(stage, previousResults) {
    const response = await fetch(
        `/api/security/assessment/${encodeURIComponent(stage.id)}`,
        {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
          body: JSON.stringify({
    assessment_id: currentAssessmentId,
    previous_results: stage.id === "report"
        ? Object.fromEntries(
            previousResults.map(item => [item.stage_id, item])
        )
        : {}
})
        }
    );

    if (response.redirected) {
        throw new Error("Phiên đăng nhập đã hết hạn.");
    }

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(
            `Backend trả về dữ liệu không hợp lệ (HTTP ${response.status}).`
        );
    }

    if (!response.ok) {
        throw new Error(
            data.message || `HTTP ${response.status}`
        );
    }

    if (!data || typeof data !== "object") {
        throw new Error("Phản hồi kiểm thử không hợp lệ.");
    }
    if (data.success === false) {
    throw new Error(
        data.message || "Backend không thể thực hiện bài kiểm thử."
    );
}
    return data;
}


// Hiển thị báo cáo cuối cùng
function renderFinalAssessmentReport(report) {
    if (!assessmentFinalReport || !assessmentReportContent) return;

    assessmentReportContent.replaceChildren();

    if (!report || typeof report !== "object") {
        const message = document.createElement("p");
        message.textContent = "Backend chưa cung cấp báo cáo chi tiết.";
        assessmentReportContent.appendChild(message);
        assessmentFinalReport.hidden = false;
        return;
    }

    const fields = [
        ["Assessment ID", report.assessment_id],
        ["Target", report.target],
        ["Total Tests", report.total_tests],
        ["Passed", report.passed],
        ["Warning", report.warning],
        ["Failed", report.failed],
        ["Overall Status", report.overall_status],
        ["Completed At", report.completed_at]
    ];

    fields.forEach(([label, value]) => {
        if (value === undefined || value === null) return;

        const row = document.createElement("p");

        const strong = document.createElement("strong");
        strong.textContent = `${label}: `;

        const span = document.createElement("span");
        span.textContent = String(value);

        row.appendChild(strong);
        row.appendChild(span);

        assessmentReportContent.appendChild(row);
    });

    if (Array.isArray(report.recommendations)) {
        const title = document.createElement("h4");
        title.textContent = "Security Recommendations";

        assessmentReportContent.appendChild(title);

        report.recommendations.forEach(item => {
            const paragraph = document.createElement("p");
            paragraph.textContent = `• ${item}`;
            assessmentReportContent.appendChild(paragraph);
        });
    }

    assessmentFinalReport.hidden = false;
}


// Khởi tạo giao diện trước khi chạy
function resetAssessmentUI() {
    assessmentResultsData = [];

    assessmentResults.replaceChildren();

    assessmentConsole.replaceChildren();

    assessmentFinalReport.hidden = true;
    assessmentReportContent.replaceChildren();

    assessmentStages.forEach(stage => {
        updateAssessmentStage(stage.id, "WAITING");
    });

    document.querySelectorAll("[data-crypto]").forEach(item => {
        const status = item.querySelector(".stage-status");

        if (status) {
            status.textContent = "WAITING";
            status.dataset.status = "waiting";
        }
    });

    updateAssessmentStatistics();
    updateAssessmentProgress(0);
}


// Chạy toàn bộ Security Assessment
async function startFullSecurityAssessment() {
    if (assessmentRunning) return;

    assessmentRunning = true;
    assessmentButton.disabled = true;
    assessmentButton.textContent = "ASSESSMENT RUNNING...";

    assessmentStatus.textContent = "RUNNING";
    assessmentConsoleStatus.textContent = "RUNNING";

    resetAssessmentUI();

    currentAssessmentId =
        `TW-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    assessmentConsoleLog("Security Assessment Engine initialized.");
    assessmentConsoleLog(`Assessment ID: ${currentAssessmentId}`);
    assessmentConsoleLog("Target: TRUEWALLET Web Application.");

    addLog(
        `Bắt đầu Integrated Security Assessment: ${currentAssessmentId}`,
        "info"
    );

    let reportData = null;

    try {
        for (let index = 0; index < assessmentStages.length; index++) {
            const stage = assessmentStages[index];

            assessmentProgressText.textContent =
                `Executing: ${stage.name}`;

            updateAssessmentStage(stage.id, "RUNNING");

            assessmentConsoleLog(
                `Starting ${stage.name}...`
            );

            try {
                const data = await executeAssessmentStage(
                    stage,
                    assessmentResultsData
                );

                const status = normalizeAssessmentStatus(data.status);

                const result = {
                    stage_id: stage.id,
                    name: stage.name,
                    status: status,
                    message: String(
                        data.message || "Không có mô tả kết quả."
                    ),
                    evidence: data.evidence ?? null
                };

                assessmentResultsData.push(result);

                updateAssessmentStage(
                    stage.id,
                    status,
                    result.message
                );

                if (data.checks) {
                    updateCryptoChecks(data.checks);
                }
if (stage.id === "report") {
    reportData = data.report || data;
}

                renderAssessmentFinding(result);

                assessmentConsoleLog(
                    `${stage.name}: ${status} - ${result.message}`,
                    status.toLowerCase()
                );

                if (status === "FAILED") {
                    addLog(
                        `${stage.name}: Kiểm thử không đạt.`,
                        "error"
                    );
                } else if (status === "WARNING") {
                    addLog(
                        `${stage.name}: Cần xem xét thêm.`,
                        "info"
                    );
                } else {
                    addLog(
                        `${stage.name}: Kiểm thử đạt.`,
                        "success"
                    );
                }

            } catch (error) {
                // Không thực hiện được kiểm thử không đồng nghĩa
                // đã chứng minh được lỗ hổng bảo mật.
                const result = {
                    stage_id: stage.id,
                    name: stage.name,
                    status: "WARNING",
                    message: `Không thể hoàn thành kiểm thử: ${error.message}`,
                    evidence: null
                };

                assessmentResultsData.push(result);

                updateAssessmentStage(
                    stage.id,
                    "WARNING",
                    result.message
                );

                renderAssessmentFinding(result);

                assessmentConsoleLog(
                    `${stage.name}: ${result.message}`,
                    "warning"
                );
            }

            updateAssessmentStatistics();
            updateAssessmentProgress(index + 1);
        }

        const passed = assessmentResultsData.filter(
            item => item.status === "PASSED"
        ).length;

        const warning = assessmentResultsData.filter(
            item => item.status === "WARNING"
        ).length;

        const failed = assessmentResultsData.filter(
            item => item.status === "FAILED"
        ).length;

        let overallStatus = "PASSED";

        if (failed > 0) {
            overallStatus = "FAILED";
        } else if (warning > 0 || passed !== assessmentStages.length) {
            overallStatus = "WARNING";
        }

        assessmentStatus.textContent = overallStatus;
        assessmentConsoleStatus.textContent = "COMPLETED";

        assessmentConsoleLog(
            `Assessment completed. PASSED: ${passed}, WARNING: ${warning}, FAILED: ${failed}.`
        );

   // Tổng hợp số liệu trực tiếp từ kết quả 8 giai đoạn
const finalReport = {
    ...(reportData || {}),

    assessment_id: currentAssessmentId,

    // Lấy địa chỉ hiện tại của TRUEWALLET
    target: window.location.origin,

    // Số liệu thực tế từ các giai đoạn đã chạy
    total_tests: assessmentResultsData.length,
    passed: passed,
    warning: warning,
    failed: failed,

    overall_status: overallStatus,

    completed_at:
        reportData?.completed_at || new Date().toISOString(),

    recommendations:
        reportData?.recommendations || [
            "Bổ sung các Security Headers còn thiếu.",
            "Bật SESSION_COOKIE_SECURE khi triển khai ứng dụng trên HTTPS.",
            "Kiểm tra lại các tiêu chí có trạng thái WARNING."
        ]
};

renderFinalAssessmentReport(finalReport);
        addLog(
            `Hoàn thành Assessment: ${overallStatus}.`,
            overallStatus === "PASSED" ? "success" : "info"
        );

    } finally {
        assessmentRunning = false;
        assessmentButton.disabled = false;
        assessmentButton.textContent = "▶ START FULL ASSESSMENT";
    }
}


// Gắn sự kiện nút Start
if (assessmentButton) {
    assessmentButton.addEventListener(
        "click",
        startFullSecurityAssessment
    );
}

// Khởi tạo trạng thái Assessment
if (assessmentStatus) {
    assessmentStatus.textContent = "READY";
}

if (assessmentConsoleStatus) {
    assessmentConsoleStatus.textContent = "STANDBY";
}

if (assessmentProgressFill) {
    assessmentProgressFill.style.width = "0%";
}
