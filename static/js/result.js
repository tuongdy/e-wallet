

// Biến lưu giao dịch hiện tại và gói mã hóa hiện tại để phục vụ demo
let currentTransaction = null;
let currentEncryptedPackage = null;
let transactionHistory = [];

let verifiedDecryptedTransaction = null;

async function verifyTransactionWithBackend() {
    verifiedDecryptedTransaction = null;

    if (!localStorage.getItem("latest_encrypted_package")) {
        return;
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
            verifiedDecryptedTransaction = result.decrypted_transaction;
        }
    } catch (error) {
        console.error("Loi xac thuc giao dich:", error);
    }
}

// 3. Khởi chạy khi trang result.html tải xong
document.addEventListener("DOMContentLoaded", async () => {
    await loadTransactionData();
    await verifyTransactionWithBackend();
    renderNormalResultView();
    renderHistoryTable();
});

// 4. Tải dữ liệu từ localStorage (do trang transfer/encryption lưu) hoặc từ API Backend, nếu chưa có thì dùng mẫu chuẩn
async function loadTransactionData() {
    try {

        const savedTx = localStorage.getItem("latest_transaction");
        const savedEnc = localStorage.getItem("latest_encrypted_package");
        const savedHistory = localStorage.getItem("e_wallet_history");

        if (savedTx) {
            currentTransaction = JSON.parse(savedTx);
        } else {
            currentTransaction = null;
        }

        if (savedEnc) {
            currentEncryptedPackage = JSON.parse(savedEnc);
        } else {
            currentEncryptedPackage = null;
        }

        if (savedHistory) {
            transactionHistory = JSON.parse(savedHistory);
        } else {
            transactionHistory = [];
        }
    } catch (error) {
        console.error("Lỗi tải dữ liệu giao dịch:", error);
        currentTransaction = null;
        currentEncryptedPackage = null;
        transactionHistory = [];
    }
}

// 5. Hiển thị thông tin giao dịch hợp lệ và bảng so sánh Client - Server
function renderNormalResultView() {
    if (!currentTransaction || !currentEncryptedPackage) {
        document.getElementById("res-tx-id").textContent = "Chưa có giao dịch";
        document.getElementById("res-sender").textContent = "-";
        document.getElementById("res-receiver").textContent = "-";
        document.getElementById("res-amount").textContent = "-";
        document.getElementById("res-content").textContent = "-";
        document.getElementById("res-timestamp").textContent = "-";

        document.getElementById("tx-status-badge").textContent = "CHƯA CÓ GIAO DỊCH";
        document.getElementById("tx-status-badge").className = "badge badge-warning";

        document.getElementById("client-plaintext-box").textContent =
            "Hãy tạo giao dịch tại /transfer trước.";
        document.getElementById("server-decrypted-box").textContent =
            "Chưa có dữ liệu giải mã.";
        document.getElementById("integrity-banner").textContent =
            "Chưa có giao dịch để xác thực.";

        document.getElementById("mitm-plaintext-view").textContent =
            "Chưa có dữ liệu giao dịch.";
        document.getElementById("mitm-encrypted-view").textContent =
            "Chưa có gói mã hóa.";
        document.getElementById("attack-log-box").textContent =
            "Hãy tạo giao dịch tại /transfer để bắt đầu kiểm thử.";

        return;
    }

    document.getElementById("res-tx-id").textContent = currentTransaction.transaction_id;
    document.getElementById("res-sender").textContent = currentTransaction.sender;
    document.getElementById("res-receiver").textContent = currentTransaction.receiver;
    document.getElementById("res-amount").textContent =
        Number(currentTransaction.amount).toLocaleString("vi-VN") + " " + currentTransaction.currency;
    document.getElementById("res-content").textContent = currentTransaction.content;
    document.getElementById("res-timestamp").textContent = currentTransaction.timestamp;


    const badge = document.getElementById("tx-status-badge");
    const clientBox = document.getElementById("client-plaintext-box");
    const serverBox = document.getElementById("server-decrypted-box");
    const banner = document.getElementById("integrity-banner");

    const formattedJson = JSON.stringify(currentTransaction, null, 2);
    clientBox.textContent = formattedJson;

    const isVerified =
        verifiedDecryptedTransaction !== null &&
        JSON.stringify(verifiedDecryptedTransaction) ===
        JSON.stringify(currentTransaction);

    if (isVerified) {
        badge.textContent = "THÀNH CÔNG (VERIFIED)";
        badge.className = "badge badge-success";

        serverBox.textContent =
            JSON.stringify(verifiedDecryptedTransaction, null, 2);
        serverBox.className = "code-box success-border";

        banner.className = "verify-banner verify-ok";
        banner.textContent =
            "XÁC THỰC THÀNH CÔNG: Server giải mã AES + RSA và dữ liệu khớp với giao dịch gốc.";
    } else {
        badge.textContent = "CHƯA XÁC THỰC";
        badge.className = "badge badge-warning";

        serverBox.textContent =
            verifiedDecryptedTransaction === null
                ? "Chưa nhận được kết quả giải mã hợp lệ từ Server."
                : JSON.stringify(verifiedDecryptedTransaction, null, 2);
        serverBox.className = "code-box danger-border";

        banner.className = "verify-banner verify-err";
        banner.textContent =
            "CHƯA XÁC THỰC: Server chưa giải mã thành công hoặc dữ liệu không khớp.";
    }

    document.getElementById("mitm-plaintext-view").textContent =
        "[Gói tin HTTP không mã hóa bị chặn]\n" + formattedJson;

    document.getElementById("mitm-encrypted-view").textContent =
        "[Gói dữ liệu được mã hóa tại Backend bằng AES-GCM + RSA-OAEP]\n" +
        JSON.stringify(currentEncryptedPackage, null, 2);


    document.getElementById("attack-log-box").textContent =
        "[QUY TRÌNH MÃ HÓA VÀ XÁC THỰC TẠI BACKEND]\n" +
        "1. Client gửi thông tin giao dịch đến Flask Backend qua API /api/transfer.\n" +
        "2. Backend tạo khóa phiên AES-256 ngẫu nhiên và mã hóa dữ liệu bằng AES-GCM.\n" +
        "3. Backend sử dụng RSA Public Key 2048-bit để mã hóa khóa phiên AES bằng RSA-OAEP.\n" +
        "4. Backend trả về gói dữ liệu mã hóa gồm encrypted_data, encrypted_key, nonce và tag.\n" +
        "5. Khi kiểm thử giải mã, Backend dùng RSA Private Key khôi phục khóa AES, xác thực GCM Tag và giải mã dữ liệu.";
}

// =========================================================================
// CÁC HÀM MÔ PHỎNG KỊCH BẢN TẤN CÔNG CỦA HACKER (PHỤC VỤ DEMO & CHƯƠNG 5)
// =========================================================================

// Kịch bản 1: Khôi phục luồng giao dịch hợp lệ bình thường
async function simulateNormalFlow() {
    await loadTransactionData();
    await verifyTransactionWithBackend();
    renderNormalResultView();
    renderHistoryTable();
}

// Kịch bản 2: Hacker chặn gói tin trên mạng và sửa đổi bản mã (Ciphertext)

async function simulateTamperCiphertext() {
    const badge = document.getElementById("tx-status-badge");
    const serverBox = document.getElementById("server-decrypted-box");
    const banner = document.getElementById("integrity-banner");
    const attackLog = document.getElementById("attack-log-box");

    if (!localStorage.getItem("latest_encrypted_package")) {
        attackLog.textContent =
            "Chưa có gói mã hóa thật. Hãy tạo giao dịch tại /transfer trước.";
        return;
    }

    const tamperedPackage = { ...currentEncryptedPackage };

    // Thay đổi một byte của ciphertext thật
    const binary = atob(tamperedPackage.encrypted_data);
    const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
    bytes[0] = bytes[0] ^ 1;

    tamperedPackage.encrypted_data = btoa(
        Array.from(bytes, b => String.fromCharCode(b)).join("")
    );

    document.getElementById("mitm-encrypted-view").textContent =
        "[Gói mã hóa đã bị thay đổi một byte]\n" +
        JSON.stringify(tamperedPackage, null, 2);

    try {
        const response = await fetch("/api/decrypt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                encrypted_transaction: tamperedPackage
            })
        });

        const result = await response.json();

        if (!response.ok && result.verified === false) {
            badge.textContent = "PHÁT HIỆN CAN THIỆP BẢN MÃ";
            badge.className = "badge badge-danger";

            serverBox.textContent =
                "Server từ chối giải mã gói dữ liệu đã bị sửa đổi.";
            serverBox.className = "code-box danger-border";

            banner.className = "verify-banner verify-err";
            banner.textContent =
                "AES-GCM: Gói dữ liệu bị can thiệp đã bị Backend từ chối.";

            attackLog.textContent =
                "[KẾT QUẢ KIỂM THỬ BACKEND]\n" +
                "HTTP Status: " + response.status + "\n" +
                "Verified: " + result.verified + "\n" +
                "Thông báo: " + result.message;
        } else {
            badge.textContent = "KIỂM TRA KHÔNG ĐẠT";
            badge.className = "badge badge-warning";

            attackLog.textContent =
                "Backend không trả về kết quả từ chối như mong đợi:\n" +
                JSON.stringify(result, null, 2);
        }
    } catch (error) {
        badge.textContent = "LỖI KẾT NỐI";
        badge.className = "badge badge-warning";

        attackLog.textContent =
            "Không thể kết nối Backend: " + error.message;
    }
}


// Kịch bản 3: Hacker cố tình dùng Khóa riêng RSA giả mạo để lấy cắp khóa phiên AES

async function simulateWrongPrivateKey() {
    const badge = document.getElementById("tx-status-badge");
    const serverBox = document.getElementById("server-decrypted-box");
    const banner = document.getElementById("integrity-banner");
    const attackLog = document.getElementById("attack-log-box");

    if (!localStorage.getItem("latest_encrypted_package")) {
        attackLog.textContent =
            "Chưa có gói mã hóa thật. Hãy tạo giao dịch tại /transfer trước.";
        return;
    }

    try {
        const response = await fetch("/api/test-wrong-key", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                encrypted_transaction: currentEncryptedPackage
            })
        });

        const result = await response.json();

        if (response.ok && result.rejected === true) {
            badge.textContent = "RSA TỪ CHỐI KHÓA KHÔNG KHỚP";
            badge.className = "badge badge-warning";

            serverBox.textContent =
                "Kiểm thử RSA-OAEP: Private Key không tương ứng " +
                "không thể giải mã khóa phiên AES.";
            serverBox.className = "code-box danger-border";

            banner.className = "verify-banner verify-err";
            banner.textContent =
                "KIỂM THỬ THÀNH CÔNG: RSA-OAEP từ chối Private Key không khớp.";

            attackLog.textContent =
                "[KẾT QUẢ KIỂM THỬ BACKEND - RSA]\n" +
                "HTTP Status: " + response.status + "\n" +
                "Rejected: " + result.rejected + "\n" +
                "Thông báo: " + result.message;
        } else {
            badge.textContent = "KIỂM TRA KHÔNG ĐẠT";
            badge.className = "badge badge-danger";

            attackLog.textContent =
                "Backend không xác nhận việc từ chối khóa RSA sai:\n" +
                JSON.stringify(result, null, 2);
        }
    } catch (error) {
        badge.textContent = "LỖI KẾT NỐI";
        badge.className = "badge badge-warning";

        attackLog.textContent =
            "Không thể kết nối Backend: " + error.message;
    }
}


// Kịch bản 4: Hacker lưu gói tin mã hóa cũ và gửi lặp lại lên Server (Replay Attack)

async function simulateReplayAttack() {
    const badge = document.getElementById("tx-status-badge");
    const serverBox = document.getElementById("server-decrypted-box");
    const banner = document.getElementById("integrity-banner");
    const attackLog = document.getElementById("attack-log-box");

    const savedPackage = localStorage.getItem("latest_encrypted_package");

    if (!savedPackage) {
        attackLog.textContent =
            "Chưa có gói mã hóa thật. Hãy tạo giao dịch tại /transfer trước.";
        return;
    }

    try {
        const encryptedPackage = JSON.parse(savedPackage);

        // Gui cung mot goi ma hoa hai lan den Backend
        const sendPackage = async () => {
            const response = await fetch("/api/test-replay", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    encrypted_transaction: encryptedPackage
                })
            });

            return {
                status: response.status,
                result: await response.json()
            };
        };

        const first = await sendPackage();
        const second = await sendPackage();

        if (
            first.status === 200 &&
            first.result.replay_detected === false &&
            second.status === 409 &&
            second.result.replay_detected === true
        ) {
            badge.textContent = "PHÁT HIỆN REPLAY ATTACK";
            badge.className = "badge badge-danger";

            serverBox.textContent =
                "Backend phát hiện transaction_id đã được ghi nhận " +
                "và từ chối xử lý giao dịch gửi lại.";
            serverBox.className = "code-box danger-border";

            banner.className = "verify-banner verify-err";
            banner.textContent =
                "REPLAY ATTACK: Giao dịch gửi lại đã bị Backend từ chối.";

            attackLog.textContent =
                "[KẾT QUẢ KIỂM THỬ BACKEND - REPLAY]\n" +
                "Lần 1 - HTTP Status: " + first.status + "\n" +
                "Replay Detected: " + first.result.replay_detected + "\n\n" +
                "Lần 2 - HTTP Status: " + second.status + "\n" +
                "Replay Detected: " + second.result.replay_detected + "\n" +
                "Thông báo: " + second.result.message;
        } else {
            badge.textContent = "CẦN KIỂM TRA KẾT QUẢ";
            badge.className = "badge badge-warning";

            attackLog.textContent =
                "[KẾT QUẢ KIỂM THỬ BACKEND - REPLAY]\n" +
                "Lần 1: HTTP " + first.status + "\n" +
                JSON.stringify(first.result, null, 2) + "\n\n" +
                "Lần 2: HTTP " + second.status + "\n" +
                JSON.stringify(second.result, null, 2);
        }
    } catch (error) {
        badge.textContent = "LỖI KIỂM THỬ";
        badge.className = "badge badge-warning";

        attackLog.textContent =
            "Không thể kiểm thử Replay Attack: " + error.message;
    }
}


// =========================================================================
// QUẢN LÝ VÀ HIỂN THỊ BẢNG LỊCH SỬ GIAO DỊCH
// =========================================================================

function renderHistoryTable() {
    const tbody = document.getElementById("history-table-body");
    tbody.innerHTML = "";

    transactionHistory.forEach((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><strong>${item.transaction_id}</strong></td>
            <td>${item.sender}</td>
            <td>${item.receiver}</td>
            <td>${Number(item.amount).toLocaleString("vi-VN")} ${item.currency}</td>
            <td>${item.content}</td>
            <td>${item.timestamp}</td>
            <td style="color: #16a34a; font-weight: 600;">${item.status || "Thành công"}</td>
        `;
        tbody.appendChild(row);
    });
}

// Hàm tạo nhanh một giao dịch mẫu mới để test lịch sử và sinh khóa phiên mới

async function addDemoTransaction() {
    const amounts = [150000, 250000, 500000, 1200000];
    const randomAmount = amounts[
        Math.floor(Math.random() * amounts.length)
    ];

    try {
        const response = await fetch("/api/transfer", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                sender: "USER_A",
                receiver: "USER_B",
                amount: randomAmount,
                currency: "VND",
                content: "Giao dich mau tu Backend"
            })
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
            alert("Không thể tạo giao dịch: " + result.message);
            return;
        }

        currentTransaction = result.transaction;
        currentEncryptedPackage = result.encrypted_transaction;

        localStorage.setItem(
            "latest_transaction",
            JSON.stringify(currentTransaction)
        );

        localStorage.setItem(
            "latest_encrypted_package",
            JSON.stringify(currentEncryptedPackage)
        );

        await verifyTransactionWithBackend();

        const isVerified =
            verifiedDecryptedTransaction !== null &&
            JSON.stringify(verifiedDecryptedTransaction) ===
            JSON.stringify(currentTransaction);

        transactionHistory.unshift({
            ...currentTransaction,
            status: isVerified
                ? "Thành công (Đã xác thực GCM)"
                : "Chưa xác thực"
        });

        localStorage.setItem(
            "e_wallet_history",
            JSON.stringify(transactionHistory)
        );

        renderNormalResultView();
        renderHistoryTable();

    } catch (error) {
        console.error("Lỗi tạo giao dịch:", error);
        alert("Không thể kết nối Backend.");
    }
}
