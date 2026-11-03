
const runButton = document.getElementById("run-tests-btn");

const totalTests = document.getElementById("total-tests");
const passedTests = document.getElementById("passed-tests");
const failedTests = document.getElementById("failed-tests");
const overallStatus = document.getElementById("overall-status");
const lastRun = document.getElementById("last-run");
const testCountLabel = document.getElementById("test-count-label");

const groups = {
    aes: document.getElementById("aes-results"),
    integrity: document.getElementById("integrity-results"),
    rsa: document.getElementById("rsa-results"),
    key: document.getElementById("key-results"),
    replay: document.getElementById("replay-results")
};

const expectedTests = [
    "AES-01",
    "AES-02",
    "INT-01",
    "INT-02",
    "RSA-01",
    "KEY-01",
    "KEY-02",
    "REPLAY-01"
];

const groupMapping = {
    "AES-01": "aes",
    "AES-02": "aes",
    "INT-01": "integrity",
    "INT-02": "integrity",
    "RSA-01": "rsa",
    "KEY-01": "key",
    "KEY-02": "key",
    "REPLAY-01": "replay"
};


// ==========================================
// RESET DASHBOARD
// ==========================================

function resetDashboard() {
    totalTests.textContent = "--";
    passedTests.textContent = "--";
    failedTests.textContent = "--";

    overallStatus.textContent = "Đang chạy...";
    overallStatus.className = "";

    testCountLabel.textContent = "Đang thực hiện kiểm thử";

    lastRun.textContent = "Vui lòng chờ kết quả";

    Object.values(groups).forEach(group => {
        group.replaceChildren();
    });
}


// ==========================================
// TAO PHAN TU KET QUA AN TOAN
// ==========================================

function createTestItem(test) {
    const item = document.createElement("div");
    item.className = "test-item";

    const information = document.createElement("div");
    information.className = "test-information";

    const id = document.createElement("div");
    id.className = "test-id";
    id.textContent = test.test_id;

    const name = document.createElement("h4");
    name.textContent = test.name;

    const message = document.createElement("p");
    message.textContent = test.message;

    information.append(id, name, message);

    const status = document.createElement("span");

    status.className = test.success
        ? "test-status pass"
        : "test-status fail";

    status.textContent = test.success ? "PASS" : "FAIL";

    item.append(information, status);

    return item;
}


// ==========================================
// KIEM TRA TINH HOP LE CUA KET QUA
// ==========================================

function validateResults(data) {
    if (!data || !Array.isArray(data.results)) {
        throw new Error("Backend không trả về danh sách kiểm thử hợp lệ.");
    }

    const results = data.results;

    if (results.length !== expectedTests.length) {
        throw new Error(
            `Số lượng kiểm thử không khớp: yêu cầu ${expectedTests.length}, nhận ${results.length}.`
        );
    }

    const receivedIds = results.map(item => item.test_id);

    if (new Set(receivedIds).size !== receivedIds.length) {
        throw new Error("Phát hiện mã kiểm thử bị trùng.");
    }

    for (const id of expectedTests) {
        if (!receivedIds.includes(id)) {
            throw new Error(`Thiếu kết quả kiểm thử ${id}.`);
        }
    }

    for (const test of results) {
        if (
            typeof test.success !== "boolean" ||
            typeof test.name !== "string" ||
            typeof test.message !== "string"
        ) {
            throw new Error(
                `Dữ liệu trả về của ${test.test_id} không hợp lệ.`
            );
        }
    }

    return results;
}


// ==========================================
// HIEN THI KET QUA
// ==========================================

function displayResults(results) {
    Object.values(groups).forEach(group => {
        group.replaceChildren();
    });

    results.forEach(test => {
        const groupName = groupMapping[test.test_id];
        const group = groups[groupName];

        if (group) {
            group.appendChild(createTestItem(test));
        }
    });
}


// ==========================================
// CAP NHAT THONG KE
// ==========================================

function updateSummary(results) {
    const total = results.length;

    const passed = results.filter(
        test => test.success === true
    ).length;

    const failed = total - passed;

    const percentage = total > 0
        ? Math.round((passed / total) * 100)
        : 0;

    totalTests.textContent = total;
    passedTests.textContent = passed;
    failedTests.textContent = failed;

    testCountLabel.textContent =
        `${total} bài kiểm thử`;

    overallStatus.className = "";

    if (failed === 0) {
        overallStatus.textContent = "Tất cả đạt";
        overallStatus.classList.add("status-pass");
    } else {
        overallStatus.textContent = "Cần kiểm tra";
        overallStatus.classList.add("status-fail");
    }

    lastRun.textContent =
        `Tỷ lệ đạt: ${percentage}% · ${new Date().toLocaleTimeString("vi-VN")}`;
}


// ==========================================
// HIEN THI LOI
// ==========================================

function displayError(message) {
    overallStatus.textContent = "Lỗi kiểm thử";
    overallStatus.className = "status-fail";

    lastRun.textContent = message;
    testCountLabel.textContent = "Không có kết quả hợp lệ";
}


// ==========================================
// CHAY KIEM THU
// ==========================================

async function runSecurityTests() {
    runButton.disabled = true;
    runButton.textContent = "Đang kiểm thử...";

    resetDashboard();

    try {
        const response = await fetch("/api/security-tests", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({})
        });

        let result;

        try {
            result = await response.json();
        } catch {
            throw new Error("Backend trả về dữ liệu không hợp lệ.");
        }

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Không thể thực hiện kiểm thử."
            );
        }

        const results = validateResults(result.data);

        updateSummary(results);
        displayResults(results);

        console.log("Security assessment:", results);

    } catch (error) {
        console.error("Security test error:", error);

        displayError(error.message);

    } finally {
        runButton.disabled = false;
        runButton.textContent = "▶ Chạy tất cả kiểm thử";
    }
}


// ==========================================
// EVENT
// ==========================================

runButton.addEventListener("click", runSecurityTests);


// ==========================================
// ATTACK SIMULATION LAB
// ==========================================

const scenarioCards = document.querySelectorAll(".scenario-card");

const scenarioTitle = document.getElementById("scenario-title");
const scenarioDescription = document.getElementById("scenario-description");
const scenarioStatus = document.getElementById("scenario-status");

const scenarioThreat = document.getElementById("scenario-threat");
const scenarioDefense = document.getElementById("scenario-defense");
const scenarioExpected = document.getElementById("scenario-expected");

const startSimulationButton = document.getElementById("start-simulation-btn");
const resetSimulationButton = document.getElementById("reset-simulation-btn");

const executionCounter = document.getElementById("execution-counter");
const executionSteps = document.getElementById("execution-steps");

const simulationData = document.getElementById("simulation-data");
const securityAnalysis = document.getElementById("security-analysis");

const eventLogCount = document.getElementById("event-log-count");
const simulationEventLog = document.getElementById("simulation-event-log");

const simulationResult = document.getElementById("simulation-result");

let selectedScenario = null;
let simulationRunning = false;
let simulationEvents = [];

const scenarios = {
    interception: {
        title: "Data Interception",
        description: "Mô phỏng quan sát dữ liệu giao dịch khi được truyền đi.",
        threat: "Người quan sát có thể nhìn thấy dữ liệu đang truyền nếu dữ liệu không được mã hóa.",
        defense: "AES-256-GCM mã hóa nội dung giao dịch trước khi truyền.",
        expected: "Người quan sát chỉ nhìn thấy ciphertext và các thành phần của gói mã hóa."
    },

    tampering: {
        title: "Data Tampering",
        description: "Kiểm tra khả năng phát hiện dữ liệu giao dịch bị thay đổi.",
        threat: "Dữ liệu mã hóa có thể bị chỉnh sửa trong quá trình truyền.",
        defense: "AES-GCM sử dụng thẻ xác thực để kiểm tra tính toàn vẹn.",
        expected: "Hệ thống phát hiện dữ liệu bị thay đổi và từ chối giải mã."
    },

    replay: {
        title: "Replay Attack",
        description: "Mô phỏng việc gửi lại cùng một gói giao dịch.",
        threat: "Một yêu cầu giao dịch cũ có thể bị gửi lại nhiều lần.",
        defense: "Transaction ID duy nhất và ràng buộc UNIQUE trong SQLite.",
        expected: "Lần gửi đầu được chấp nhận, lần gửi lại bị từ chối."
    },

    rsa: {
        title: "RSA Key Attack",
        description: "Kiểm tra việc sử dụng khóa riêng RSA không tương ứng.",
        threat: "Người không có khóa riêng phù hợp cố gắng khôi phục khóa AES.",
        defense: "RSA-OAEP kết hợp SHA-256 bảo vệ khóa phiên AES.",
        expected: "Khóa RSA không phù hợp bị từ chối."
    },

    unauthorized: {
        title: "Unauthorized Access",
        description: "Kiểm tra khả năng truy cập API khi không có phiên đăng nhập.",
        threat: "Người chưa đăng nhập cố gắng truy cập chức năng kiểm thử bảo mật.",
        defense: "Flask login_required kiểm tra trạng thái đăng nhập.",
        expected: "Yêu cầu không có phiên đăng nhập được chuyển đến trang đăng nhập."
    },

    hybrid: {
        title: "Hybrid Encryption",
        description: "Mô phỏng toàn bộ quy trình mã hóa và giải mã AES + RSA.",
        threat: "Dữ liệu giao dịch cần được bảo vệ trong quá trình truyền và xử lý.",
        defense: "AES mã hóa dữ liệu; RSA bảo vệ khóa phiên AES.",
        expected: "Server khôi phục khóa AES, giải mã và xác thực dữ liệu thành công."
    }
};


// ==========================================
// HIEN THI NHAT KY SU KIEN
// ==========================================

function addSimulationLog(message, type = "info") {
    const item = document.createElement("div");
    item.className = `simulation-log-item ${type}`;

    const time = document.createElement("span");
    time.className = "simulation-log-time";
    time.textContent = new Date().toLocaleTimeString("vi-VN");

    const content = document.createElement("span");
    content.textContent = message;

    item.append(time, content);
    simulationEventLog.prepend(item);

    simulationEvents.push(message);
    eventLogCount.textContent = simulationEvents.length;
}


// ==========================================
// HIEN THI CAC BUOC THUC HIEN
// ==========================================

function addExecutionStep(title, description, status = "completed") {
    const step = document.createElement("div");
    step.className = `execution-step ${status}`;

    const heading = document.createElement("h4");
    heading.textContent = title;

    const detail = document.createElement("p");
    detail.textContent = description;

    step.append(heading, detail);
    executionSteps.appendChild(step);

    executionCounter.textContent =
        `${executionSteps.children.length} bước`;
}


// ==========================================
// HIEN THI DU LIEU AN TOAN
// ==========================================

function showSimulationData(title, data) {
    simulationData.replaceChildren();

    const heading = document.createElement("h4");
    heading.textContent = title;

    const pre = document.createElement("pre");
    pre.textContent = typeof data === "string"
        ? data
        : JSON.stringify(data, null, 2);

    simulationData.append(heading, pre);
}


function showSecurityAnalysis(message) {
    securityAnalysis.textContent = message;
}


// ==========================================
// RESET MO PHONG
// ==========================================

function resetSimulation() {
    executionSteps.replaceChildren();
    simulationEventLog.replaceChildren();

    simulationData.replaceChildren();
    securityAnalysis.textContent = "";

    simulationResult.textContent = "";
    simulationResult.className = "";

    executionCounter.textContent = "0 bước";
    eventLogCount.textContent = "0";

    scenarioStatus.textContent = "Sẵn sàng";
    scenarioStatus.className = "";

    simulationEvents = [];
}


// ==========================================
// CHON KICH BAN
// ==========================================

function selectScenario(scenarioId) {
    if (!scenarios[scenarioId] || simulationRunning) {
        return;
    }

    selectedScenario = scenarioId;
        startSimulationButton.disabled = false;

    scenarioCards.forEach(card => {
        card.classList.toggle(
            "active",
            card.dataset.scenario === scenarioId
        );
    });

    const scenario = scenarios[scenarioId];

    scenarioTitle.textContent = scenario.title;
    scenarioDescription.textContent = scenario.description;
    scenarioThreat.textContent = scenario.threat;
    scenarioDefense.textContent = scenario.defense;
    scenarioExpected.textContent = scenario.expected;

    resetSimulation();

    addSimulationLog(
        `Đã chọn kịch bản: ${scenario.title}`
    );
}


// ==========================================
// GOI API BACKEND
// ==========================================

async function simulationRequest(url, body = {}) {
    const response = await fetch(url, {
        method: "POST",
        credentials: "same-origin",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
    });

    let result;

    try {
        result = await response.json();
    } catch {
        throw new Error("Backend không trả về JSON hợp lệ.");
    }

    if (!response.ok) {
        throw new Error(
            result.message || `Lỗi HTTP ${response.status}`
        );
    }

    return result;
}


// ==========================================
// TAO GOI GIAO DICH GIA LAP
// ==========================================

async function createSimulationPackage() {
    addExecutionStep(
        "Bước 1: Tạo giao dịch",
        "Tạo dữ liệu giao dịch giả lập, không sử dụng số dư thật."
    );

    addSimulationLog("Đang tạo giao dịch giả lập...");

    const result = await simulationRequest(
        "/api/simulation/package"
    );

    if (!result.success) {
        throw new Error(result.message);
    }

    addExecutionStep(
        "Bước 2: Mã hóa giao dịch",
        "AES mã hóa dữ liệu và RSA bảo vệ khóa phiên."
    );

    addSimulationLog("Đã tạo gói giao dịch mã hóa.", "success");

    return result;
}


// ==========================================
// KICH BAN 1: DATA INTERCEPTION
// ==========================================

async function runInterception() {
    const result = await createSimulationPackage();

    const encrypted = result.encrypted_transaction;

    showSimulationData(
        "Dữ liệu mà người quan sát mô phỏng nhìn thấy",
        {
            transaction_id: encrypted.transaction_id,
            encrypted_data: encrypted.encrypted_data,
            encrypted_key: encrypted.encrypted_key,
            nonce: encrypted.nonce,
            tag: encrypted.tag
        }
    );

    addExecutionStep(
        "Bước 3: Quan sát dữ liệu truyền đi",
        "Người quan sát chỉ nhìn thấy gói dữ liệu đã mã hóa, không thấy nội dung giao dịch gốc."
    );

    showSecurityAnalysis(
        "AES-256-GCM bảo vệ nội dung giao dịch. RSA-OAEP bảo vệ khóa AES. " +
        "Đây là mô phỏng quan sát dữ liệu mã hóa, không thực hiện bắt gói tin mạng thật."
    );

    addSimulationLog(
        "Người quan sát chỉ nhìn thấy dữ liệu mã hóa.",
        "success"
    );

    return {
        passed: true,
        message: "Dữ liệu giao dịch được mã hóa trước khi truyền."
    };
}


// ==========================================
// KICH BAN 2: DATA TAMPERING
// ==========================================

async function runTampering() {
    const packageResult = await createSimulationPackage();

    addExecutionStep(
        "Bước 3: Thay đổi bản sao dữ liệu",
        "Backend thay đổi ciphertext trong bản sao kiểm thử."
    );

    addSimulationLog("Đang kiểm tra tính toàn vẹn...");

    const result = await simulationRequest(
        "/api/simulation/tampering",
        {
            encrypted_transaction:
                packageResult.encrypted_transaction
        }
    );

    addExecutionStep(
        "Bước 4: Xác thực AES-GCM",
        result.message
    );

    showSimulationData(
        "Kết quả kiểm tra dữ liệu",
        {
            tampering_detected: result.rejected,
            message: result.message
        }
    );

    showSecurityAnalysis(
        "AES-GCM sử dụng authentication tag để phát hiện dữ liệu bị thay đổi. " +
        "Gói kiểm thử bị từ chối và giao dịch gốc không bị chỉnh sửa."
    );

    addSimulationLog(
        result.rejected
            ? "AES-GCM phát hiện dữ liệu bị thay đổi."
            : "Không phát hiện được thay đổi.",
        result.rejected ? "success" : "error"
    );

    return {
        passed: result.success && result.rejected,
        message: result.message
    };
}


// ==========================================
// KICH BAN 3: REPLAY ATTACK
// ==========================================

async function runReplay() {
    const packageResult = await createSimulationPackage();

    addExecutionStep(
        "Bước 3: Gửi giao dịch lần đầu",
        "Backend ghi nhận Transaction ID vào SQLite."
    );

    const result = await simulationRequest(
        "/api/simulation/replay",
        {
            encrypted_transaction:
                packageResult.encrypted_transaction
        }
    );

    addExecutionStep(
        "Bước 4: Gửi lại cùng giao dịch",
        "Hệ thống kiểm tra Transaction ID đã tồn tại."
    );

    addExecutionStep(
        "Bước 5: Xử lý yêu cầu trùng",
        result.message
    );

    showSimulationData(
        "Kết quả mô phỏng Replay",
        {
            transaction_id: result.transaction_id,
            first_request_accepted: result.first_request_accepted,
            replay_rejected: result.replay_rejected
        }
    );

    showSecurityAnalysis(
        "Ràng buộc UNIQUE trong SQLite ngăn cùng Transaction ID được ghi nhận hai lần. " +
        "Bản ghi thử nghiệm được xóa sau khi kiểm tra."
    );

    addSimulationLog(
        result.replay_rejected
            ? "Yêu cầu gửi lại bị từ chối."
            : "Cảnh báo: yêu cầu gửi lại chưa bị từ chối.",
        result.replay_rejected ? "success" : "error"
    );

    return {
        passed: result.success &&
            result.first_request_accepted &&
            result.replay_rejected,
        message: result.message
    };
}


// ==========================================
// KICH BAN 4: RSA KEY ATTACK
// ==========================================

async function runRsaAttack() {
    const packageResult = await createSimulationPackage();

    addExecutionStep(
        "Bước 3: Thử sử dụng khóa RSA không phù hợp",
        "Kiểm tra khả năng giải mã khóa AES bằng khóa riêng khác."
    );

    const result = await simulationRequest(
        "/api/test-wrong-key",
        {
            encrypted_transaction:
                packageResult.encrypted_transaction
        }
    );

    const details = result.data || result;

    const rejected = details.rejected === true;

    addExecutionStep(
        "Bước 4: Kiểm tra kết quả RSA-OAEP",
        details.message || "Đã hoàn tất kiểm tra khóa RSA."
    );

    showSimulationData(
        "Kết quả kiểm tra khóa RSA",
        {
            wrong_private_key_rejected: rejected,
            message: details.message || result.message
        }
    );

    showSecurityAnalysis(
        "RSA-OAEP sử dụng khóa riêng tương ứng để khôi phục khóa AES. " +
        "Khóa riêng không phù hợp không thể giải mã khóa phiên."
    );

    addSimulationLog(
        rejected
            ? "RSA-OAEP từ chối khóa riêng không phù hợp."
            : "Không xác nhận được việc từ chối khóa RSA.",
        rejected ? "success" : "error"
    );

    return {
        passed: rejected,
        message: details.message || result.message
    };
}


// ==========================================
// KICH BAN 5: UNAUTHORIZED ACCESS
// ==========================================

async function runUnauthorized() {
    addExecutionStep(
        "Bước 1: Tạo yêu cầu không có phiên đăng nhập",
        "Gửi yêu cầu kiểm thử mà không gửi cookie đăng nhập."
    );

    addSimulationLog(
        "Đang kiểm tra quyền truy cập API..."
    );

    const response = await fetch("/api/security-tests", {
        method: "POST",
        credentials: "omit",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({})
    });

    addExecutionStep(
        "Bước 2: Kiểm tra phản hồi của server",
        response.redirected
            ? "Server chuyển yêu cầu đến trang đăng nhập."
            : `Server trả về HTTP ${response.status}.`
    );

    const redirectedToLogin =
        response.redirected &&
        new URL(response.url).pathname === "/login";

    showSimulationData(
        "Kết quả kiểm tra truy cập",
        {
            request_has_login_cookie: false,
            redirected_to_login: redirectedToLogin,
            final_status: response.status
        }
    );

    showSecurityAnalysis(
        "Route /api/security-tests sử dụng login_required. " +
        "Khi không có phiên đăng nhập, server chuyển yêu cầu đến trang đăng nhập. " +
        "Cookie đăng nhập thật của trình duyệt không bị xóa hoặc thay đổi."
    );

    addSimulationLog(
        redirectedToLogin
            ? "Truy cập trái phép bị chuyển đến trang đăng nhập."
            : "Cần kiểm tra lại phản hồi xác thực của server.",
        redirectedToLogin ? "success" : "error"
    );

    return {
        passed: redirectedToLogin,
        message: redirectedToLogin
            ? "Server đã từ chối yêu cầu không có phiên đăng nhập."
            : "Không xác nhận được cơ chế chuyển hướng đăng nhập."
    };
}


// ==========================================
// KICH BAN 6: HYBRID ENCRYPTION
// ==========================================

async function runHybrid() {
    const packageResult = await createSimulationPackage();

    addExecutionStep(
        "Bước 3: RSA khôi phục khóa AES",
        "Server sử dụng RSA Private Key để giải mã khóa phiên."
    );

    addExecutionStep(
        "Bước 4: AES giải mã giao dịch",
        "AES-GCM giải mã và xác thực nội dung giao dịch."
    );

    const result = await simulationRequest(
        "/api/simulation/hybrid",
        {
            transaction: packageResult.transaction,
            encrypted_transaction:
                packageResult.encrypted_transaction
        }
    );

    addExecutionStep(
        "Bước 5: Đối chiếu dữ liệu",
        result.verified
            ? "Dữ liệu sau giải mã khớp với dữ liệu ban đầu."
            : "Dữ liệu sau giải mã không khớp."
    );

    showSimulationData(
        "Thông tin kiểm chứng",
        {
            verified: result.verified,
            key_id: result.key_id,
            key_fingerprint: result.key_fingerprint
        }
    );

    showSecurityAnalysis(
        "Mô hình mã hóa lai kết hợp ưu điểm của hai thuật toán: " +
        "AES xử lý dữ liệu giao dịch, RSA bảo vệ khóa phiên. " +
        "Khóa AES thực tế không được hiển thị trên giao diện."
    );

    addSimulationLog(
        result.verified
            ? "Quy trình AES + RSA hoàn tất và dữ liệu khớp."
            : "Quy trình kiểm chứng không thành công.",
        result.verified ? "success" : "error"
    );

    return {
        passed: result.success && result.verified,
        message: result.message
    };
}


// ==========================================
// DIEU PHOI CAC KICH BAN
// ==========================================

async function startSimulation() {
    if (!selectedScenario || simulationRunning) {
        return;
    }

    simulationRunning = true;
    startSimulationButton.disabled = true;
    resetSimulationButton.disabled = true;

    resetSimulation();

    scenarioStatus.textContent = "Đang mô phỏng...";
    scenarioStatus.className = "status-running";

    simulationResult.textContent = "";

    addSimulationLog(
        `Bắt đầu: ${scenarios[selectedScenario].title}`
    );

    const simulationFunctions = {
        interception: runInterception,
        tampering: runTampering,
        replay: runReplay,
        rsa: runRsaAttack,
        unauthorized: runUnauthorized,
        hybrid: runHybrid
    };

    try {
        const result = await simulationFunctions[selectedScenario]();

        scenarioStatus.textContent = result.passed
            ? "Đã phát hiện / phòng vệ thành công"
            : "Cần kiểm tra";

        scenarioStatus.className = result.passed
            ? "status-pass"
            : "status-fail";

        simulationResult.textContent = result.message;

        simulationResult.className = result.passed
            ? "simulation-result success"
            : "simulation-result failed";

        addSimulationLog(
            result.passed
                ? "Kịch bản hoàn tất: cơ chế phòng vệ hoạt động đúng."
                : "Kịch bản hoàn tất: cần kiểm tra cơ chế phòng vệ.",
            result.passed ? "success" : "error"
        );

    } catch (error) {
        console.error("Simulation error:", error);

        scenarioStatus.textContent = "Lỗi mô phỏng";
        scenarioStatus.className = "status-fail";

        simulationResult.textContent = error.message;
        simulationResult.className = "simulation-result failed";

        addSimulationLog(
            `Lỗi: ${error.message}`,
            "error"
        );

    } finally {
        simulationRunning = false;
        startSimulationButton.disabled = false;
        resetSimulationButton.disabled = false;
    }
}


// ==========================================
// RESET VA EVENT
// ==========================================

function resetCurrentSimulation() {
    if (simulationRunning) {
        return;
    }

    resetSimulation();

    scenarioStatus.textContent = "Sẵn sàng";

    addSimulationLog("Đã đặt lại kịch bản.");
}

scenarioCards.forEach(card => {
    card.addEventListener("click", () => {
        selectScenario(card.dataset.scenario);
    });
});

startSimulationButton.addEventListener(
    "click",
    startSimulation
);

resetSimulationButton.addEventListener(
    "click",
    resetCurrentSimulation
);


// ==========================================
// LIVE SECURITY MONITORING
// ==========================================

const monitorConnection = document.getElementById("monitoring-connection");
const monitorServer = document.getElementById("monitor-server");
const monitorDatabase = document.getElementById("monitor-database");
const monitorEncryption = document.getElementById("monitor-encryption");

const monitorTotal = document.getElementById("monitor-total-events");
const monitorBlocked = document.getElementById("monitor-blocked-events");
const monitorSuccess = document.getElementById("monitor-success-events");

const monitoringEventsList = document.getElementById("monitoring-events-list");
const monitoringLastUpdate = document.getElementById("monitoring-last-update");
const refreshMonitoringButton = document.getElementById("refresh-monitoring");


// Chuyển thời gian UTC thành giờ Việt Nam
function formatMonitoringTime(timestamp) {
    if (!timestamp) return "--";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) return "--";

    return date.toLocaleString("vi-VN", {
        timeZone: "Asia/Ho_Chi_Minh"
    });
}


// Hiển thị trạng thái an toàn
function setMonitoringStatus(element, value, status) {
    element.textContent = value;
    element.className = `monitoring-value ${status}`;
}


// Gửi yêu cầu GET đến backend
async function getMonitoringData(url) {
    const response = await fetch(url, {
        method: "GET",
        credentials: "same-origin",
        headers: {
            "Accept": "application/json"
        }
    });

    if (response.status === 401 || response.redirected) {
        throw new Error("Phiên đăng nhập không hợp lệ.");
    }

    const contentType = response.headers.get("content-type") || "";

    if (!contentType.includes("application/json")) {
        throw new Error(`Backend trả về dữ liệu không phải JSON (HTTP ${response.status}).`);
    }

    const data = await response.json();

    if (!response.ok || !data.success) {
        throw new Error(data.message || `HTTP ${response.status}`);
    }

    return data;
}


// Lấy trạng thái server và database
async function updateSystemStatus() {
    const data = await getMonitoringData("/api/security/status");

    setMonitoringStatus(
        monitorServer,
        data.server.toUpperCase(),
        data.server === "online" ? "monitor-online" : "monitor-offline"
    );

    setMonitoringStatus(
        monitorDatabase,
        data.database.toUpperCase(),
        data.database === "connected" ? "monitor-online" : "monitor-offline"
    );

    monitorEncryption.textContent = data.encryption || "--";
}


// Lấy thống kê sự kiện
async function updateEventSummary() {
    const data = await getMonitoringData("/api/security/summary");

    monitorTotal.textContent = data.summary.total_events;
    monitorBlocked.textContent = data.summary.blocked_events;
    monitorSuccess.textContent = data.summary.successful_events;
}


// Tạo một hàng trong bảng nhật ký
function createMonitoringRow(event) {
    const row = document.createElement("tr");

    const values = [
        formatMonitoringTime(event.timestamp),
        event.event_type || "--",
        event.scenario || "--",
        event.http_status ?? "--",
        event.result || "--",
        event.message || "--"
    ];

    values.forEach((value, index) => {
        const cell = document.createElement("td");

        cell.textContent = String(value);

        if (index === 4) {
            const result = String(event.result || "").toUpperCase();

            cell.className = result === "BLOCKED" || result === "SUCCESS"
                ? "event-result success"
                : result === "NOT_BLOCKED" || result === "MISMATCH"
                    ? "event-result warning"
                    : "event-result";
        }

        row.appendChild(cell);
    });

    return row;
}


// Lấy danh sách sự kiện
async function updateSecurityEvents() {
    const data = await getMonitoringData("/api/security/events?limit=50");

    monitoringEventsList.replaceChildren();

    if (!Array.isArray(data.events) || data.events.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.textContent = "Chưa có sự kiện bảo mật nào.";

        row.appendChild(cell);
        monitoringEventsList.appendChild(row);

        return;
    }

    data.events.forEach(event => {
        monitoringEventsList.appendChild(
            createMonitoringRow(event)
        );
    });
}


// Cập nhật toàn bộ Security Monitoring
async function refreshSecurityMonitoring() {
    if (refreshMonitoringButton) {
        refreshMonitoringButton.disabled = true;
    }

    try {
        await Promise.all([
            updateSystemStatus(),
            updateEventSummary(),
            updateSecurityEvents()
        ]);

        monitorConnection.textContent = "● CONNECTED";
        monitorConnection.className = "monitoring-badge connected";

        monitoringLastUpdate.textContent =
            "Cập nhật lần cuối: " +
            new Date().toLocaleTimeString("vi-VN");

    } catch (error) {
        console.error("Live monitoring error:", error);

        monitorConnection.textContent = "● DISCONNECTED";
        monitorConnection.className = "monitoring-badge disconnected";

        monitoringLastUpdate.textContent =
            "Không thể cập nhật: " + error.message;

    } finally {
        if (refreshMonitoringButton) {
            refreshMonitoringButton.disabled = false;
        }
    }
}


// Nút cập nhật thủ công
if (refreshMonitoringButton) {
    refreshMonitoringButton.addEventListener(
        "click",
        refreshSecurityMonitoring
    );
}


// Tự động cập nhật mỗi 2 giây
refreshSecurityMonitoring();

setInterval(refreshSecurityMonitoring, 2000);

