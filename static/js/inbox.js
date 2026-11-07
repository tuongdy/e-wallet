document.addEventListener("DOMContentLoaded", () => {
    loadTransactions();
});

const transactionList = document.getElementById("transaction-list");
const alertBox = document.getElementById("alert");

function showAlert(message, type) {
    alertBox.textContent = message;
    alertBox.className = type;
}

async function loadTransactions() {
    transactionList.textContent = "Đang tải giao dịch...";

    try {
        const response = await fetch("/api/inbox");
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || "Không thể tải giao dịch");
        }

        transactionList.replaceChildren();

        if (result.transactions.length === 0) {
            transactionList.textContent = "Bạn chưa có giao dịch nhận tiền nào.";
            return;
        }

        result.transactions.forEach(transaction => {
            const card = document.createElement("div");
            card.className = "transaction-card";

            const title = document.createElement("h3");
            title.textContent = "Giao dịch " + transaction.transaction_id;

            const sender = document.createElement("p");
            sender.textContent = "Người gửi: " + transaction.sender;

            const amount = document.createElement("p");
            amount.textContent =
                "Số tiền: " +
                Number(transaction.amount).toLocaleString("vi-VN") +
                " " + transaction.currency;

            const content = document.createElement("p");
            content.textContent = "Nội dung: " + (transaction.content || "Không có");

            const time = document.createElement("p");
            time.textContent = "Thời gian: " + formatVietnamTime(transaction.timestamp);

            const status = document.createElement("p");
            status.textContent = transaction.status === "received"
                ? "Trạng thái: Đã xác nhận nhận tiền"
                : "Trạng thái: Đang chờ xác nhận";

            card.append(title, sender, amount, content, time, status);

            if (transaction.status === "pending") {
                const button = document.createElement("button");
                button.textContent = "Xác nhận đã nhận tiền";

                button.addEventListener("click", () => {
                    confirmTransaction(transaction.transaction_id, button);
                });

                card.appendChild(button);
            }

            transactionList.appendChild(card);
        });

    } catch (error) {
        transactionList.textContent = error.message;
    }
}

async function confirmTransaction(transactionId, button) {
    if (!confirm("Bạn có chắc chắn muốn xác nhận đã nhận giao dịch này?")) {
        return;
    }

    button.disabled = true;

    try {
        const response = await fetch(
            `/api/transactions/${encodeURIComponent(transactionId)}/confirm`,
            { method: "POST" }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || "Không thể xác nhận giao dịch");
        }

        showAlert(result.message, "success");
        await loadTransactions();

    } catch (error) {
        showAlert(error.message, "error");
        button.disabled = false;
    }
}
function formatVietnamTime(timestamp) {
    if (!timestamp) return "Không xác định";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleString("vi-VN", {
        timeZone: "Asia/Ho_Chi_Minh",
        hour12: false
    });
}