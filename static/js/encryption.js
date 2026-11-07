
const result = document.getElementById("result");

const transactionInfo = document.getElementById("transaction-info");
const encryptionSteps = document.getElementById("encryption-steps");
const sessionKeyInfo = document.getElementById("session-key-info");
const sessionKeyHistory = document.getElementById("session-key-history");
const verificationResult = document.getElementById("verification-result");

function createTextElement(tag, text, className = "") {
    const element = document.createElement(tag);
    element.textContent = text;

    if (className) {
        element.className = className;
    }

    return element;
}

function formatVietnamTime(timestamp) {
    if (!timestamp) return "Không có dữ liệu";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return "Không xác định";
    }

    const formatted = new Intl.DateTimeFormat("vi-VN", {
        timeZone: "Asia/Ho_Chi_Minh",
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
    }).format(date);

    return `${formatted} (GMT+7)`;
}

// Hien thi cac buoc xu ly AES va RSA
function renderEncryptionSteps(encrypted, data) {
    encryptionSteps.replaceChildren();

    const steps = [
        {
            title: "Tạo khóa phiên AES-256",
            description: "Hệ thống tạo một khóa AES ngẫu nhiên dài 256 bit cho giao dịch.",
            algorithm: "AES-256",
            input: "Dữ liệu giao dịch ban đầu",
            output: "Khóa phiên AES được tạo ngẫu nhiên",
            explanation: "AES là thuật toán mã hóa đối xứng. Cùng một khóa được sử dụng để mã hóa và giải mã dữ liệu. Mỗi giao dịch sử dụng một khóa phiên riêng.",
            status: "Đã tạo"
        },
        {
            title: "Mã hóa dữ liệu bằng AES-GCM",
            description: "Dữ liệu giao dịch được mã hóa bằng khóa phiên AES.",
            algorithm: "AES-256-GCM",
            input: "Dữ liệu giao dịch và khóa phiên AES",
            output: "Ciphertext, Nonce và Authentication Tag",
            explanation: "AES-GCM vừa mã hóa dữ liệu vừa tạo thẻ xác thực. Nonce là giá trị được sử dụng trong quá trình mã hóa; Authentication Tag hỗ trợ kiểm tra tính toàn vẹn và xác thực dữ liệu.",
            status: "Đã mã hóa"
        },
        {
            title: "Bảo vệ khóa AES bằng RSA",
            description: "Khóa phiên AES được mã hóa bằng khóa công khai RSA của máy chủ.",
            algorithm: "RSA-OAEP + SHA-256",
            input: "Khóa phiên AES và khóa công khai RSA",
            output: "Encrypted AES Key",
            explanation: "RSA là thuật toán mã hóa bất đối xứng. Khóa công khai RSA được dùng để bảo vệ khóa phiên AES, giúp chỉ bên có khóa riêng tương ứng mới có thể khôi phục khóa.",
            status: "Đã bảo vệ khóa"
        },
        {
            title: "Khôi phục khóa phiên",
            description: "Máy chủ sử dụng khóa riêng RSA để giải mã khóa phiên AES.",
            algorithm: "RSA-OAEP + SHA-256",
            input: "Encrypted AES Key và khóa riêng RSA",
            output: "Khóa phiên AES được khôi phục",
            explanation: "Máy chủ sử dụng khóa riêng RSA tương ứng với khóa công khai đã dùng trước đó. Khóa AES được khôi phục để chuẩn bị giải mã dữ liệu giao dịch. Khóa thật không được hiển thị.",
            status: "Đã khôi phục"
        },
        {
            title: "Giải mã dữ liệu giao dịch",
            description: "Khóa AES được khôi phục sử dụng để giải mã ciphertext.",
            algorithm: "AES-256-GCM",
            input: "Ciphertext, khóa AES và Nonce",
            output: "Dữ liệu giao dịch sau giải mã",
            explanation: "Sau khi khôi phục khóa AES, máy chủ sử dụng khóa này cùng các thông số cần thiết để giải mã dữ liệu giao dịch.",
            status: "Đã giải mã"
        },
        {
            title: "Kiểm tra tính toàn vẹn",
            description: data.verified
                ? "Dữ liệu đã được xác thực thành công."
                : "Dữ liệu không vượt qua bước xác thực.",
            algorithm: "AES-GCM Authentication",
            input: "Ciphertext, Authentication Tag và dữ liệu giải mã",
            output: data.verified
                ? "Dữ liệu hợp lệ"
                : "Dữ liệu không hợp lệ",
            explanation: data.verified
                ? "AES-GCM xác thực thành công. Dữ liệu sau giải mã khớp với giao dịch ban đầu."
                : "Quá trình xác thực không thành công. Hệ thống không nên chấp nhận dữ liệu này.",
            status: data.verified ? "Thành công" : "Thất bại"
        }
    ];

    let currentStep = 0;

    // Tạo khu vực tiến trình
    const progressWrapper = document.createElement("div");
    progressWrapper.className = "flow-progress";

    const progressText = createTextElement(
        "p",
        "Tiến trình: 0/6 bước",
        "flow-progress-text"
    );

    const progressTrack = document.createElement("div");
    progressTrack.className = "flow-progress-track";

    const progressBar = document.createElement("div");
    progressBar.className = "flow-progress-bar";

    progressTrack.appendChild(progressBar);
    progressWrapper.append(progressText, progressTrack);

    // Tạo sơ đồ 6 bước
    const flowNavigation = document.createElement("div");
    flowNavigation.className = "flow-navigation";

    const stepButtons = [];

    steps.forEach((step, index) => {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "flow-step-button";

        button.appendChild(
            createTextElement("span", `0${index + 1}`, "flow-step-number")
        );

        button.appendChild(
            createTextElement("span", step.title, "flow-step-title")
        );

        button.addEventListener("click", () => {
            currentStep = index;
            updateFlow();
        });

        stepButtons.push(button);
        flowNavigation.appendChild(button);
    });

    // Khu vực nội dung từng bước
    const detailPanel = document.createElement("div");
    detailPanel.className = "flow-detail-panel";

    // Các nút điều khiển
    const controls = document.createElement("div");
    controls.className = "flow-controls";

    const previousButton = createTextElement(
        "button",
        "← Bước trước",
        "flow-control-button"
    );
    previousButton.type = "button";

    const nextButton = createTextElement(
        "button",
        "Bước tiếp theo →",
        "flow-control-button primary"
    );
    nextButton.type = "button";

    const runAllButton = createTextElement(
        "button",
        "Chạy toàn bộ quy trình",
        "flow-control-button run-all"
    );
    runAllButton.type = "button";

    controls.append(previousButton, nextButton, runAllButton);

    // Hiển thị dữ liệu thực tế tương ứng với từng bước
    function getStepOutput(index) {
        switch (index) {
            case 0:
                return "Khóa phiên AES đã được tạo ở phía xử lý mã hóa. Vì lý do bảo mật, khóa thật không được hiển thị.";

            case 1:
                return JSON.stringify({
                    encrypted_data: encrypted.encrypted_data,
                    nonce: encrypted.nonce,
                    tag: encrypted.tag
                }, null, 2);

            case 2:
                return JSON.stringify({
                    encrypted_key: encrypted.encrypted_key
                }, null, 2);

            case 3:
                return JSON.stringify({
                    key_id: encrypted.key_id || "Không có dữ liệu",
                    key_fingerprint: encrypted.key_fingerprint || "Không có dữ liệu",
                    key_created_at: encrypted.key_created_at || "Không có dữ liệu"
                }, null, 2);

            case 4:
                return JSON.stringify(
                    data.decrypted_transaction || {},
                    null,
                    2
                );

            case 5:
                return data.verified
                    ? "VERIFICATION PASSED\nDữ liệu giao dịch đã được xác thực."
                    : "VERIFICATION FAILED\nDữ liệu giao dịch không được xác thực.";

            default:
                return "";
        }
    }

    function updateFlow() {
        const step = steps[currentStep];

        progressText.textContent =
            `Tiến trình: ${currentStep + 1}/6 bước`;

        progressBar.style.width =
            `${((currentStep + 1) / steps.length) * 100}%`;

        stepButtons.forEach((button, index) => {
            button.classList.toggle("active", index === currentStep);
            button.classList.toggle("completed", index < currentStep);
        });

        detailPanel.replaceChildren();

        detailPanel.appendChild(
            createTextElement("span", `BƯỚC 0${currentStep + 1}`, "flow-label")
        );

        detailPanel.appendChild(
            createTextElement("h3", step.title)
        );

        detailPanel.appendChild(
            createTextElement("p", step.description)
        );

        const status = createTextElement(
            "span",
            step.status,
            data.verified === false && currentStep === 5
                ? "flow-status failed"
                : "flow-status success"
        );

        detailPanel.appendChild(status);

        const infoGrid = document.createElement("div");
        infoGrid.className = "flow-info-grid";

        [
            ["Thuật toán", step.algorithm],
            ["Đầu vào", step.input],
            ["Đầu ra", step.output]
        ].forEach(([label, value]) => {
            const box = document.createElement("div");
            box.className = "flow-info-box";

            box.appendChild(createTextElement("strong", label));
            box.appendChild(createTextElement("p", value));

            infoGrid.appendChild(box);
        });

        detailPanel.appendChild(infoGrid);

        detailPanel.appendChild(
            createTextElement("h4", "Giải thích kỹ thuật")
        );

        detailPanel.appendChild(
            createTextElement("p", step.explanation)
        );

        detailPanel.appendChild(
            createTextElement("h4", "Dữ liệu đầu ra thực tế")
        );

        const output = createTextElement(
            "pre",
            getStepOutput(currentStep),
            "flow-output"
        );

        detailPanel.appendChild(output);

        previousButton.disabled = currentStep === 0;
        nextButton.disabled = currentStep === steps.length - 1;

        nextButton.textContent =
            currentStep === steps.length - 1
                ? "Đã đến bước cuối"
                : "Bước tiếp theo →";
    }

    previousButton.addEventListener("click", () => {
        if (currentStep > 0) {
            currentStep--;
            updateFlow();
        }
    });

    nextButton.addEventListener("click", () => {
        if (currentStep < steps.length - 1) {
            currentStep++;
            updateFlow();
        }
    });

    runAllButton.addEventListener("click", () => {
        currentStep = steps.length - 1;
        updateFlow();
    });

    progressWrapper.appendChild(flowNavigation);
    encryptionSteps.append(
        progressWrapper,
        flowNavigation,
        detailPanel,
        controls
    );

    updateFlow();
}

// Hien thi thong tin khoa phien
function renderSessionKeyInfo(encrypted) {
    sessionKeyInfo.replaceChildren();

    if (!encrypted.key_id) {
        sessionKeyInfo.appendChild(
            createTextElement(
                "p",
                "Giao dịch này chưa có thông tin khóa phiên. Có thể giao dịch được tạo trước khi bổ sung chức năng quản lý khóa."
            )
        );
        return;
    }

    const fields = [
        ["Mã định danh khóa", encrypted.key_id],
        ["Thuật toán", "AES-256-GCM"],
        ["Thời điểm tạo", formatVietnamTime(encrypted.key_created_at)],
        ["Dấu vân tay khóa", encrypted.key_fingerprint || "Không có dữ liệu"],
        ["Trạng thái", "Đã sử dụng cho giao dịch này"]
    ];

    fields.forEach(([label, value]) => {
        const row = document.createElement("p");
        row.appendChild(createTextElement("strong", label + ": "));
        row.appendChild(document.createTextNode(String(value)));
        sessionKeyInfo.appendChild(row);
    });

    sessionKeyInfo.appendChild(
        createTextElement(
            "p",
            "Khóa AES thật không được hiển thị trên giao diện."
        )
    );
}

// Hien thi ket qua xac thuc
function renderVerification(data) {
    verificationResult.replaceChildren();

    const success = data.verified === true;

    verificationResult.appendChild(
        createTextElement(
            "h3",
            success
                ? "Xác thực thành công"
                : "Xác thực không thành công"
        )
    );

    verificationResult.appendChild(
        createTextElement(
            "p",
            success
                ? "Dữ liệu sau khi giải mã khớp với dữ liệu giao dịch ban đầu."
                : "Dữ liệu không được xác thực. Cần kiểm tra lại gói mã hóa."
        )
    );
}

// Tao mot o trong bang lich su
function createCell(text) {
    return createTextElement("td", text);
}

// Tai lich su khoa phien tu cac giao dich
async function loadSessionKeyHistory() {
    sessionKeyHistory.replaceChildren();

    try {
        const response = await fetch("/api/my-transactions");
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.message || "Không thể tải lịch sử giao dịch.");
        }

        const transactions = data.transactions || [];

        if (transactions.length === 0) {
            sessionKeyHistory.appendChild(
                createTextElement("p", "Chưa có giao dịch nào.")
            );
            return;
        }

        const table = document.createElement("table");
        const thead = document.createElement("thead");
        const headerRow = document.createElement("tr");

        ["Mã giao dịch", "Mã khóa phiên", "Thời điểm tạo", "Dấu vân tay"]
            .forEach(title => {
                headerRow.appendChild(createTextElement("th", title));
            });

        thead.appendChild(headerRow);

        const tbody = document.createElement("tbody");

        // Lay toi da 20 giao dich gan nhat
        const recentTransactions = transactions.slice(0, 20);

        const historyResults = await Promise.all(
            recentTransactions.map(async transaction => {
                try {
                    const detailResponse = await fetch(
                        `/api/transactions/${encodeURIComponent(transaction.transaction_id)}/encryption`
                    );

                    const detail = await detailResponse.json();

                    if (!detailResponse.ok || !detail.success) {
                        return null;
                    }

                    return {
                        transaction_id: transaction.transaction_id,
                        encrypted: detail.encrypted_transaction
                    };
                } catch (error) {
                    console.error("Lỗi tải giao dịch:", error);
                    return null;
                }
            })
        );

        let foundKey = false;

        historyResults.forEach(item => {
            if (!item || !item.encrypted) {
                return;
            }

            const encrypted = item.encrypted;

            if (!encrypted.key_id) {
                return;
            }

            foundKey = true;

            const row = document.createElement("tr");

            row.appendChild(createCell(item.transaction_id));
            row.appendChild(createCell(encrypted.key_id));
            row.appendChild(
    createCell(formatVietnamTime(encrypted.key_created_at))
);
            row.appendChild(
                createCell(
                    encrypted.key_fingerprint
                        ? encrypted.key_fingerprint.substring(0, 16) + "..."
                        : "Không có dữ liệu"
                )
            );

            tbody.appendChild(row);
        });

        if (!foundKey) {
            sessionKeyHistory.appendChild(
                createTextElement(
                    "p",
                    "Chưa tìm thấy thông tin khóa phiên. Hãy tạo giao dịch mới sau khi cập nhật crypto.py."
                )
            );
            return;
        }

        table.append(thead, tbody);
        sessionKeyHistory.appendChild(table);

        sessionKeyHistory.appendChild(
            createTextElement(
                "p",
                "Danh sách hiển thị tối đa 20 giao dịch gần nhất có thông tin khóa phiên."
            )
        );

    } catch (error) {
        sessionKeyHistory.textContent =
            "Lỗi tải lịch sử khóa phiên: " + error.message;
    }
}

// Tai quy trinh ma hoa cua giao dich duoc chon
async function loadEncryptionProcess() {
    result.textContent = "Đang tải thông tin giao dịch...";

    try {
        const params = new URLSearchParams(window.location.search);
        const transactionId = params.get("transaction_id");

        if (!transactionId) {
            throw new Error("Không tìm thấy mã giao dịch.");
        }

        const response = await fetch(
            `/api/transactions/${encodeURIComponent(transactionId)}/encryption`
        );

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.message || "Không thể tải giao dịch.");
        }

        const encrypted = data.encrypted_transaction;
        const transaction = data.transaction;

        // 1. Thong tin giao dich
        transactionInfo.textContent =
            `Mã giao dịch: ${transaction.transaction_id}
Người gửi: ${transaction.sender}
Người nhận: ${transaction.receiver}
Số tiền: ${Number(transaction.amount).toLocaleString("vi-VN")} ${transaction.currency}
Nội dung: ${transaction.content}
Thời gian: ${formatVietnamTime(transaction.timestamp)}`;

        // 2. Cac buoc ma hoa
        renderEncryptionSteps(encrypted, data);

        // 3. Thong tin khoa phien
        renderSessionKeyInfo(encrypted);

        // 4. Ket qua xac thuc
        renderVerification(data);

        // 5. Du lieu chi tiet
        result.textContent = JSON.stringify({
            transaction: transaction,
            encrypted_transaction: encrypted,
            decrypted_transaction: data.decrypted_transaction,
            verified: data.verified
        }, null, 2);

        // 6. Lich su khoa phien
        await loadSessionKeyHistory();

    } catch (error) {
        result.textContent = "Lỗi: " + error.message;
        transactionInfo.textContent = "Không thể tải thông tin giao dịch.";
        encryptionSteps.textContent = "Không thể tải quá trình mã hóa.";
        sessionKeyInfo.textContent = "Không có thông tin khóa phiên.";
        verificationResult.textContent = "Chưa thể xác thực dữ liệu.";
    }
}

loadEncryptionProcess();
