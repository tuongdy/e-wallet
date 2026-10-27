
const form = document.getElementById("encryption-form");
const result = document.getElementById("result");

form.addEventListener("submit", async function (event) {
    event.preventDefault();

    result.textContent = "Đang mã hóa và giải mã...";

    const transaction = {
        transaction_id: document.getElementById("transaction_id").value,
        sender: document.getElementById("sender").value.trim(),
        receiver: document.getElementById("receiver").value.trim(),
        amount: Number(document.getElementById("amount").value),
        currency: "VND",
        content: document.getElementById("content").value.trim(),
        timestamp: new Date(
            document.getElementById("timestamp").value
        ).toISOString()
    };

    try {
        const response = await fetch("/api/encryption-demo", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(transaction)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Có lỗi khi xử lý giao dịch.");
        }

        result.textContent = JSON.stringify(data, null, 2);

    } catch (error) {
        result.textContent =
            "Không thể xử lý: " + error.message +
            "\nHãy kiểm tra backend và API /api/encryption-demo.";
    }
});
