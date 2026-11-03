
// ============================================================
// TRUEWALLET - TRANSACTION RESULT
// Chỉ phụ trách hiển thị kết quả và lịch sử giao dịch.
// Các chức năng mô phỏng tấn công được chuyển sang security.js.
// ============================================================

let currentTransaction = null;
let currentEncryptedPackage = null;
let transactionHistory = [];
let verifiedDecryptedTransaction = null;


// ============================================================
// 1. HÀM HỖ TRỢ
// ============================================================

function getElement(id) {
    return document.getElementById(id);
}

function formatVietnamTime(timestamp) {
    if (!timestamp) return "--";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return "Không xác định";
    }

    return new Intl.DateTimeFormat("vi-VN", {
        timeZone: "Asia/Ho_Chi_Minh",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
    }).format(date) + " (GMT+7)";
}

function formatAmount(amount, currency = "VND") {
    const number = Number(amount);

    if (!Number.isFinite(number)) {
        return "--";
    }

    return number.toLocaleString("vi-VN") + " " + currency;
}

function compareTransactions(original, decrypted) {
    if (!original || !decrypted) {
        return false;
    }

    const fields = [
        "transaction_id",
        "sender",
        "receiver",
        "amount",
        "currency",
        "content",
        "timestamp"
    ];

    return fields.every(field => {
        if (field === "amount") {
            return Number(original[field]) === Number(decrypted[field]);
        }

        return String(original[field] ?? "") ===
            String(decrypted[field] ?? "");
    });
}


// ============================================================
// 2. KHỞI CHẠY TRANG
// ============================================================

document.addEventListener("DOMContentLoaded", async () => {
    const refreshButton = getElement("refresh-history-btn");
    const searchInput = getElement("history-search-input");
    const clearSearchButton = getElement("clear-history-search");

    if (refreshButton) {
        refreshButton.addEventListener("click", loadTransactionData);
    }

    // Tìm kiếm khi người dùng nhập nội dung.
    if (searchInput) {
        searchInput.addEventListener("input", () => {
            renderHistoryTable();
        });
    }

    // Xóa từ khóa và hiển thị lại toàn bộ giao dịch.
    if (clearSearchButton) {
        clearSearchButton.addEventListener("click", () => {
            if (searchInput) {
                searchInput.value = "";
                searchInput.focus();
            }

            renderHistoryTable();
        });
    }

    await loadTransactionData();
});

// ============================================================
// 3. TẢI LỊCH SỬ GIAO DỊCH TỪ BACKEND
// ============================================================

async function loadTransactionData() {
    const refreshButton = getElement("refresh-history-btn");

    if (refreshButton) {
        refreshButton.disabled = true;
        refreshButton.textContent = "Đang tải...";
    }

    try {
        const response = await fetch("/api/my-transactions");
        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Không thể tải lịch sử giao dịch."
            );
        }

        transactionHistory = Array.isArray(result.transactions)
            ? result.transactions
            : [];

        if (transactionHistory.length > 0) {
            // Mặc định hiển thị giao dịch mới nhất.
            const latestTransaction = transactionHistory[0];

            await loadTransactionDetails(
                latestTransaction.transaction_id
            );
        } else {
            currentTransaction = null;
            currentEncryptedPackage = null;
            verifiedDecryptedTransaction = null;

            renderTransactionInfo();
            renderProcessingSteps();
            renderDataComparison();
        }

        renderHistoryTable();

    } catch (error) {
        console.error("Lỗi tải dữ liệu giao dịch:", error);

        currentTransaction = null;
        currentEncryptedPackage = null;
        verifiedDecryptedTransaction = null;
        transactionHistory = [];

        renderTransactionInfo();
        renderProcessingSteps();
        renderDataComparison();
        renderHistoryTable();

        const verificationBox = getElement("verification-result");

        if (verificationBox) {
            verificationBox.textContent =
                "Không thể tải dữ liệu từ Backend: " + error.message;
        }

    } finally {
        if (refreshButton) {
            refreshButton.disabled = false;
            refreshButton.textContent = "↻ Làm mới";
        }
    }
}


// ============================================================
// 4. TẢI CHI TIẾT MỘT GIAO DỊCH
// ============================================================

async function loadTransactionDetails(transactionId) {
    try {
        const response = await fetch(
            `/api/transactions/${encodeURIComponent(transactionId)}/encryption`
        );

        const result = await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message || "Không thể tải chi tiết giao dịch."
            );
        }

        currentTransaction = {
            ...result.transaction,
            status: result.status ?? result.transaction?.status
        };

        currentEncryptedPackage = result.encrypted_transaction || null;

        verifiedDecryptedTransaction =
            result.verified === true
                ? result.decrypted_transaction
                : null;

        // Nếu Backend chưa trả kết quả giải mã,
        // gửi gói mã hóa đến API giải mã để xác thực.
        if (
            currentEncryptedPackage &&
            verifiedDecryptedTransaction === null
        ) {
            await verifyTransactionWithBackend();
        }

        renderTransactionInfo();
        renderProcessingSteps();
        renderDataComparison();
        renderHistoryTable();

    } catch (error) {
        console.error("Lỗi tải chi tiết giao dịch:", error);

        const verificationBox = getElement("verification-result");

        if (verificationBox) {
            verificationBox.textContent =
                "Không thể tải chi tiết giao dịch: " + error.message;
        }
    }
}


// ============================================================
// 5. XÁC THỰC GIẢI MÃ VỚI BACKEND
// ============================================================

async function verifyTransactionWithBackend() {
    verifiedDecryptedTransaction = null;

    if (!currentEncryptedPackage) {
        return false;
    }

    try {
        const response = await fetch("/api/decrypt", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                encrypted_transaction: currentEncryptedPackage
            })
        });

        const result = await response.json();

        if (response.ok && result.verified === true) {
            verifiedDecryptedTransaction =
                result.decrypted_transaction;

            console.log("Giải mã và xác thực thành công.");

            return true;
        }

        console.error("Backend không xác thực được dữ liệu:", result);

        return false;

    } catch (error) {
        console.error("Lỗi kết nối API giải mã:", error);

        return false;
    }
}


// ============================================================
// 6. HIỂN THỊ THÔNG TIN GIAO DỊCH
// ============================================================

function renderTransactionInfo() {
    const statusBadge = getElement("transaction-status");

    if (!currentTransaction) {
        getElement("result-amount").textContent = "-- VND";
        getElement("result-transaction-id").textContent =
            "Transaction ID: --";

        getElement("result-sender").textContent = "--";
        getElement("result-receiver").textContent = "--";
        getElement("result-content").textContent = "--";
        getElement("result-timestamp").textContent = "--";

        if (statusBadge) {
            statusBadge.textContent = "Chưa có giao dịch";
            statusBadge.className =
                "status-badge status-pending";
        }

        return;
    }

    getElement("result-amount").textContent = formatAmount(
        currentTransaction.amount,
        currentTransaction.currency
    );

    getElement("result-transaction-id").textContent =
        "Transaction ID: " +
        (currentTransaction.transaction_id || "--");

    getElement("result-sender").textContent =
        currentTransaction.sender || "--";

    getElement("result-receiver").textContent =
        currentTransaction.receiver || "--";

    getElement("result-content").textContent =
        currentTransaction.content || "--";

    getElement("result-timestamp").textContent =
        formatVietnamTime(currentTransaction.timestamp);

    if (statusBadge) {
        const status = currentTransaction.status;

        if (status === "received") {
            statusBadge.textContent = "Đã xác nhận nhận tiền";
            statusBadge.className =
                "status-badge status-success";

        } else if (status === "pending") {
            statusBadge.textContent = "Đang chờ xác nhận";
            statusBadge.className =
                "status-badge status-pending";

        } else if (status) {
            statusBadge.textContent = status;
            statusBadge.className =
                "status-badge status-pending";

        } else {
            statusBadge.textContent = "Chưa xác định";
            statusBadge.className =
                "status-badge status-pending";
        }
    }
}


// ============================================================
// 7. HIỂN THỊ QUY TRÌNH XỬ LÝ GIAO DỊCH
// ============================================================

function renderProcessingSteps() {
    const container = getElement("processing-steps");

    if (!container) return;

    container.replaceChildren();

    if (!currentTransaction) {
        const empty = document.createElement("div");
        empty.className = "empty-state";

        const title = document.createElement("strong");
        title.textContent = "Chưa có dữ liệu xử lý";

        const description = document.createElement("p");
        description.textContent =
            "Hãy tạo giao dịch tại trang Chuyển tiền để xem tiến trình.";

        empty.append(title, description);
        container.appendChild(empty);

        return;
    }

    const hasEncryptedData =
        currentEncryptedPackage &&
        Boolean(currentEncryptedPackage.encrypted_data);

    const hasEncryptedKey =
        currentEncryptedPackage &&
        Boolean(currentEncryptedPackage.encrypted_key);

    const isVerified = compareTransactions(
        currentTransaction,
        verifiedDecryptedTransaction
    );

    const steps = [
        {
            title: "Tiếp nhận thông tin giao dịch",
            description: "Backend đã ghi nhận thông tin giao dịch.",
            completed: true
        },
        {
            title: "Mã hóa dữ liệu bằng AES-GCM",
            description: "Kiểm tra gói dữ liệu mã hóa AES.",
            completed: hasEncryptedData
        },
        {
            title: "Bảo vệ khóa phiên bằng RSA-OAEP",
            description: "Kiểm tra khóa AES đã được mã hóa bằng khóa công khai RSA.",
            completed: hasEncryptedKey
        },
        {
            title: "Giải mã và xác thực dữ liệu",
            description: isVerified
                ? "Dữ liệu sau giải mã khớp với dữ liệu ban đầu."
                : "Chưa xác nhận được dữ liệu sau giải mã.",
            completed: isVerified
        }
    ];

    steps.forEach((step, index) => {
        const item = document.createElement("div");
        item.className = "processing-step";

        const marker = document.createElement("div");
        marker.className = step.completed
            ? "step-marker completed"
            : "step-marker pending";

        marker.textContent = step.completed ? "✓" : (index + 1);

        const content = document.createElement("div");
        content.className = "step-content";

        const title = document.createElement("strong");
        title.textContent = step.title;

        const description = document.createElement("p");
        description.textContent = step.description;

        const state = document.createElement("span");
        state.className = step.completed
            ? "step-state completed"
            : "step-state pending";

        state.textContent = step.completed
            ? "Đã hoàn thành"
            : "Chưa xác nhận";

        content.append(title, description, state);
        item.append(marker, content);

        container.appendChild(item);
    });
}


// ============================================================
// 8. ĐỐI CHIẾU DỮ LIỆU CLIENT VÀ SERVER
// ============================================================

function renderDataComparison() {
    const originalBox = getElement("original-data");
    const decryptedBox = getElement("decrypted-data");
    const verificationBox = getElement("verification-result");

    if (!currentTransaction) {
        originalBox.textContent = "Chưa có dữ liệu giao dịch.";
        decryptedBox.textContent = "Chưa có dữ liệu giải mã.";

        verificationBox.textContent =
            "Chưa có giao dịch để đối chiếu.";

        verificationBox.className = "verification-message";

        return;
    }

    originalBox.textContent = JSON.stringify(
        currentTransaction,
        null,
        2
    );

    if (!verifiedDecryptedTransaction) {
        decryptedBox.textContent =
            "Server chưa trả về dữ liệu giải mã hợp lệ.";

        verificationBox.textContent =
            "Chưa thể xác thực dữ liệu giao dịch.";

        verificationBox.className =
            "verification-message verification-warning";

        return;
    }

    decryptedBox.textContent = JSON.stringify(
        verifiedDecryptedTransaction,
        null,
        2
    );

    const isMatched = compareTransactions(
        currentTransaction,
        verifiedDecryptedTransaction
    );

    if (isMatched) {
        verificationBox.textContent =
            "XÁC THỰC THÀNH CÔNG: Dữ liệu sau giải mã trùng khớp với dữ liệu giao dịch ban đầu.";

        verificationBox.className =
            "verification-message verification-success";

    } else {
        verificationBox.textContent =
            "CẢNH BÁO: Dữ liệu sau giải mã không trùng khớp với dữ liệu ban đầu.";

        verificationBox.className =
            "verification-message verification-error";
    }
}


// ============================================================
// 9. TÌM KIẾM VÀ HIỂN THỊ LỊCH SỬ GIAO DỊCH
// ============================================================

// Lọc giao dịch theo mã giao dịch, người gửi hoặc người nhận.
function filterTransactionHistory() {
    const searchInput = getElement("history-search-input");

    const keyword = searchInput
        ? searchInput.value.trim().toLowerCase()
        : "";

    if (!keyword) {
        return transactionHistory;
    }

    return transactionHistory.filter(item => {
        const transactionId = String(
            item.transaction_id ?? ""
        ).toLowerCase();

        const sender = String(
            item.sender ?? ""
        ).toLowerCase();

        const receiver = String(
            item.receiver ?? ""
        ).toLowerCase();

        return (
            transactionId.includes(keyword) ||
            sender.includes(keyword) ||
            receiver.includes(keyword)
        );
    });
}


// Hiển thị số lượng giao dịch phù hợp với từ khóa.
function updateHistorySearchCount(filteredTransactions) {
    const countElement = getElement("history-search-count");

    if (!countElement) return;

    const total = transactionHistory.length;
    const filtered = filteredTransactions.length;

    const searchInput = getElement("history-search-input");
    const keyword = searchInput
        ? searchInput.value.trim()
        : "";

    if (total === 0) {
        countElement.textContent = "Chưa có giao dịch nào.";
        return;
    }

    if (keyword) {
        countElement.textContent =
            `Tìm thấy ${filtered} / ${total} giao dịch`;
    } else {
        countElement.textContent =
            `Hiển thị tất cả ${total} giao dịch`;
    }
}


// Hiển thị bảng lịch sử giao dịch.
function renderHistoryTable() {
    const tbody = getElement("transaction-history");

    if (!tbody) return;

    tbody.replaceChildren();

    const filteredTransactions = filterTransactionHistory();

    updateHistorySearchCount(filteredTransactions);

    // Trường hợp hệ thống chưa có giao dịch.
    if (transactionHistory.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.className = "table-empty";
        cell.textContent = "Chưa có giao dịch nào được ghi nhận.";

        row.appendChild(cell);
        tbody.appendChild(row);

        return;
    }

    // Trường hợp không tìm thấy giao dịch phù hợp.
    if (filteredTransactions.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 6;
        cell.className = "table-empty";
        cell.textContent =
            "Không tìm thấy giao dịch phù hợp với từ khóa tìm kiếm.";

        row.appendChild(cell);
        tbody.appendChild(row);

        return;
    }

    // Hiển thị các giao dịch phù hợp.
    filteredTransactions.forEach(item => {
        const row = document.createElement("tr");

        const values = [
            item.transaction_id,
            item.sender,
            item.receiver,
            formatAmount(item.amount, item.currency),
            formatVietnamTime(item.timestamp),
            getTransactionStatusLabel(item.status)
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value ?? "--";
            row.appendChild(cell);
        });

        row.style.cursor = "pointer";
        row.title = "Chọn để xem chi tiết giao dịch";

        row.addEventListener("click", async () => {
            await loadTransactionDetails(item.transaction_id);

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });
        });

        tbody.appendChild(row);
    });
}


// Chuyển trạng thái giao dịch sang tiếng Việt.
function getTransactionStatusLabel(status) {
    if (status === "pending") {
        return "Đang chờ xác nhận";
    }

    if (status === "received") {
        return "Đã xác nhận nhận tiền";
    }

    return status || "Chưa xác định";
}