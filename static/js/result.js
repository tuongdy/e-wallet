// 1. Dữ liệu giao dịch gốc
const DEFAULT_TRANSACTION = {
    transaction_id: "GD001",
    sender: "USER_A",
    receiver: "USER_B",
    amount: 100000,
    currency: "VND",
    content: "Chuyen tien",
    timestamp: "2026-10-21T19:00:00"
};

// Biến lưu giao dịch hiện tại và gói mã hóa hiện tại để phục vụ demo
let currentTransaction = null;
let currentEncryptedPackage = null;
let transactionHistory = [];

// 2. Hàm giả lập chuỗi Base64 thực tế khi chạy độc lập (hoặc lấy từ Backend nếu đã ghép)
function generateSimulatedEncryptedPackage(txData) {
    const jsonStr = JSON.stringify(txData);
    // Mã hóa Base64 giả lập bản mã dựa trên dữ liệu gốc
    const rawB64 = btoa(unescape(encodeURIComponent(jsonStr)));

    return {
        encrypted_aes_key: "dK8vP2mX9qL4nR7wT1yU6jH3fB8vN4mX2cT9kL1pQxR7yVz5wM8nJ3bH6dF4aS9dF2gH5jK8lZ1xC4vB7nM0qW3eR6tY9uI2oP5==",
        nonce: "rT5yU8iO2pA4sD6fG1hJ9k==",
        tag: "zX3cV6bN8mQ1wE4rT7yU0i==",
        ciphertext: rawB64.split('').reverse().join('') + "9vR8zL9kPq2XmW4aN7cT1y=="
    };
}

// 3. Khởi chạy khi trang result.html tải xong
document.addEventListener("DOMContentLoaded", async () => {
    await loadTransactionData();
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
            currentTransaction = { ...DEFAULT_TRANSACTION };
        }

        if (savedEnc) {
            currentEncryptedPackage = JSON.parse(savedEnc);
        } else {
            currentEncryptedPackage = generateSimulatedEncryptedPackage(currentTransaction);
        }

        if (savedHistory) {
            transactionHistory = JSON.parse(savedHistory);
        } else {
            transactionHistory = [
                {
                    ...currentTransaction,
                    status: "Thành công (Đã xác thực GCM)"
                }
            ];
            localStorage.setItem("e_wallet_history", JSON.stringify(transactionHistory));
        }
    } catch (error) {
        console.warn("Sử dụng dữ liệu mẫu mặc định:", error);
        currentTransaction = { ...DEFAULT_TRANSACTION };
        currentEncryptedPackage = generateSimulatedEncryptedPackage(currentTransaction);
    }
}

// 5. Hiển thị thông tin giao dịch hợp lệ và bảng so sánh Client - Server
function renderNormalResultView() {
    
    document.getElementById("res-tx-id").textContent = currentTransaction.transaction_id;
    document.getElementById("res-sender").textContent = currentTransaction.sender;
    document.getElementById("res-receiver").textContent = currentTransaction.receiver;
    document.getElementById("res-amount").textContent =
        Number(currentTransaction.amount).toLocaleString("vi-VN") + " " + currentTransaction.currency;
    document.getElementById("res-content").textContent = currentTransaction.content;
    document.getElementById("res-timestamp").textContent = currentTransaction.timestamp;

    const badge = document.getElementById("tx-status-badge");
    badge.textContent = "THÀNH CÔNG (VERIFIED)";
    badge.className = "badge badge-success";

    
    const formattedJson = JSON.stringify(currentTransaction, null, 2);
    document.getElementById("client-plaintext-box").textContent = formattedJson;
    document.getElementById("server-decrypted-box").textContent = formattedJson;
    document.getElementById("server-decrypted-box").className = "code-box success-border";

    const banner = document.getElementById("integrity-banner");
    banner.className = "verify-banner verify-ok";
    banner.textContent =
        "KIỂM TRA TOÀN VẸN THÀNH CÔNG: Payload ban đầu tại Client == Payload sau khi Server giải mã (Khớp 100%).";

    
    document.getElementById("mitm-plaintext-view").textContent =
        "[Gói tin HTTP không mã hóa bị chặn]\n" + formattedJson;

    document.getElementById("mitm-encrypted-view").textContent =
        "[Gói tin đã bảo vệ bằng AES-GCM + RSA-OAEP]\n" +
        JSON.stringify(currentEncryptedPackage, null, 2);

    document.getElementById("attack-log-box").textContent =
        "[TRẠNG THÁI HỆ THỐNG: AN TOÀN]\n" +
        "1. Client tạo khóa phiên AES-256 ngẫu nhiên (32 byte) và mã hóa giao dịch bằng chế độ AES-GCM.\n" +
        "2. Khóa phiên AES được bọc an toàn bằng RSA-OAEP (Public Key 2048-bit của Server).\n" +
        "3. Server dùng RSA Private Key khôi phục khóa AES -> Xác thực Tag hợp lệ -> Giải mã thành công!";
}

// =========================================================================
// CÁC HÀM MÔ PHỎNG KỊCH BẢN TẤN CÔNG CỦA HACKER (PHỤC VỤ DEMO & CHƯƠNG 5)
// =========================================================================

// Kịch bản 1: Khôi phục luồng giao dịch hợp lệ bình thường
function simulateNormalFlow() {
    currentEncryptedPackage = generateSimulatedEncryptedPackage(currentTransaction);
    renderNormalResultView();
}

// Kịch bản 2: Hacker chặn gói tin trên mạng và sửa đổi bản mã (Ciphertext)
function simulateTamperCiphertext() {
    
    const tamperedPackage = { ...currentEncryptedPackage };
    tamperedPackage.ciphertext = "HACKED_999999_" + tamperedPackage.ciphertext.substring(14);

    
    document.getElementById("mitm-encrypted-view").textContent =
        "[Gói tin đã bị Hacker sửa đổi]\n" +
        JSON.stringify(tamperedPackage, null, 2);

    
    const badge = document.getElementById("tx-status-badge");
    badge.textContent = "BỊ TỪ CHỐI (DỮ LIỆU BỊ SỬA ĐỔI)";
    badge.className = "badge badge-danger";

    const serverBox = document.getElementById("server-decrypted-box");
    serverBox.textContent =
        "[LỖI GIẢI MÃ TẠI SERVER]\n" +
        "ValueError: MAC check failed!\n\n" +
        "=> Thuật toán AES-GCM phát hiện bản mã (ciphertext) không khớp với thẻ xác thực (tag).\n" +
        "=> Server lập tức hủy bỏ và không thực hiện chuyển tiền";
    serverBox.className = "code-box danger-border";

    const banner = document.getElementById("integrity-banner");
    banner.className = "verify-banner verify-err";
    banner.textContent =
        "CẢNH BÁO BẢO MẬT (TC08): Phát hiện hành vi can thiệp bản mã trên đường truyền! Giao dịch đã bị chặn.";

    document.getElementById("attack-log-box").textContent =
        "[NHẬT KÝ PHÒNG THỦ - KỊCH BẢN SỬA ĐỔI CIPHERTEXT]\n" +
        "- Hành vi của Hacker: Chặn gói tin JSON và thay đổi byte trong trường 'ciphertext' nhằm mục đích đổi số tiền.\n" +
        "- Phản ứng của Server: Khôi phục được khóa AES nhưng khi gọi hàm decrypt_and_verify(), phép kiểm tra GHASH thất bại do Tag không khớp.\n" +
        "- Kết quả: Báo lỗi 'ValueError: MAC check failed' và từ chối giao dịch.";
}

// Kịch bản 3: Hacker cố tình dùng Khóa riêng RSA giả mạo để lấy cắp khóa phiên AES
function simulateWrongPrivateKey() {
    const badge = document.getElementById("tx-status-badge");
    badge.textContent = "CHẶN TRUY CẬP KHÓA TRÁI PHÉP";
    badge.className = "badge badge-warning";

    const serverBox = document.getElementById("server-decrypted-box");
    serverBox.textContent =
        "[MÔ PHỎNG TẠI MÁY CỦA KẺ TẤN CÔNG]\n" +
        "ValueError: Incorrect decryption (PKCS#1 OAEP)\n\n" +
        "=> Kẻ tấn công không có RSA Private Key của Server nên không thể giải mã trường 'encrypted_aes_key'.\n" +
        "=> Khóa phiên AES-256 được bảo vệ an toàn tuyệt đối!";
    serverBox.className = "code-box danger-border";

    const banner = document.getElementById("integrity-banner");
    banner.className = "verify-banner verify-err";
    banner.textContent =
        "BẢO VỆ KHÓA THÀNH CÔNG (TC06): Khóa riêng RSA không tương ứng không thể khôi phục khóa phiên AES.";

    document.getElementById("attack-log-box").textContent =
        "[NHẬT KÝ PHÒNG THỦ - KỊCH BẢN DÙNG SAI KHÓA RIÊNG RSA]\n" +
        "- Hành vi của Hacker: Thu thập gói tin trên mạng và tự sinh cặp khóa RSA-2048 giả để thử giải mã 'encrypted_aes_key'.\n" +
        "- Cơ chế bảo vệ: RSA-OAEP kiểm tra cấu trúc đệm SHA-256. Vì khóa riêng không khớp với khóa công khai của Server, quá trình giải mã thất bại ngay lập tức.\n" +
        "- Kết quả: Kẻ tấn công không lấy được khóa AES, nội dung giao dịch vẫn an toàn.";
}

// Kịch bản 4: Hacker lưu gói tin mã hóa cũ và gửi lặp lại lên Server (Replay Attack)
function simulateReplayAttack() {
    const badge = document.getElementById("tx-status-badge");
    badge.textContent = "TỪ CHỐI GIAO DỊCH LẶP (REPLAY)";
    badge.className = "badge badge-danger";

    const serverBox = document.getElementById("server-decrypted-box");
    serverBox.textContent =
        "[CẢNH BÁO TẤN CÔNG PHÁT LẠI - REPLAY ATTACK]\n" +
        `Mã giao dịch '${currentTransaction.transaction_id}' đã tồn tại trong lịch sử hệ thống!\n\n` +
        "=> Server từ chối xử lý lại gói tin cũ để tránh trừ tiền hai lần.";
    serverBox.className = "code-box danger-border";

    const banner = document.getElementById("integrity-banner");
    banner.className = "verify-banner verify-err";
    banner.textContent =
        "NGĂN CHẶN REPLAY ATTACK (TC10): Phát hiện gói tin cũ bị gửi lại thông qua kiểm tra trùng mã giao dịch (transaction_id).";

    document.getElementById("attack-log-box").textContent =
        "[NHẬT KÝ PHÒNG THỦ - KỊCH BẢN GỬI LẠI GIAO DỊCH CŨ]\n" +
        "- Hành vi của Hacker: Sao chép nguyên vẹn gói tin mã hóa hợp lệ trước đó và gửi lại lên API '/api/transfer'.\n" +
        "- Phản ứng của hệ thống: Đối chiếu 'transaction_id' và 'timestamp' với danh sách giao dịch đã xử lý.\n" +
        "- Kết quả: Phát hiện trùng mã định danh '" + currentTransaction.transaction_id + "', hủy yêu cầu phát lại.";
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
function addDemoTransaction() {
    const randomId = "GD-" + Math.random().toString(16).substring(2, 8).toUpperCase();
    const amounts = [150000, 250000, 500000, 1200000];
    const randomAmount = amounts[Math.floor(Math.random() * amounts.length)];
    const nowIso = new Date().toISOString().split('.')[0];

    const newTx = {
        transaction_id: randomId,
        sender: "USER_A",
        receiver: "USER_B",
        amount: randomAmount,
        currency: "VND",
        content: "Thanh toan hoa don " + randomId,
        timestamp: nowIso
    };

    currentTransaction = newTx;
    currentEncryptedPackage = generateSimulatedEncryptedPackage(newTx);

    transactionHistory.unshift({
        ...newTx,
        status: "Thành công (Đã xác thực GCM)"
    });

    
    localStorage.setItem("latest_transaction", JSON.stringify(currentTransaction));
    localStorage.setItem("latest_encrypted_package", JSON.stringify(currentEncryptedPackage));
    localStorage.setItem("e_wallet_history", JSON.stringify(transactionHistory));

    renderNormalResultView();
    renderHistoryTable();
}