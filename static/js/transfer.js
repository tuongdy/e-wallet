// ===================== CẤU HÌNH =====================
const API_URL = "/api/transfer";

// true  = giả lập server (test khi backend chưa xong)
// false = gửi thật đến API_URL
const USE_MOCK = false;

const form = document.getElementById("transfer-form");
const submitBtn = document.getElementById("submit-btn");
const alertBox = document.getElementById("alert");
const resultBox = document.getElementById("result");
const resultJson = document.getElementById("result-json");

function pad(n) {
  return String(n).padStart(2, "0");
}

// Trả về dạng "2026-10-21T19:00:00"
function getTimestamp() {
  const d = new Date();
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` +
    `T${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

// Tạo mã giao dịch dạng GD + số
function generateTransactionId() {
  return "GD" + Date.now();
}

function showAlert(message, type) {
  alertBox.textContent = message;
  alertBox.className = "alert " + type;
}

function hideAlert() {
  alertBox.className = "alert hidden";
}

function clearErrors() {
  document.querySelectorAll(".error").forEach((el) => (el.textContent = ""));
  document.querySelectorAll("input").forEach((el) => el.classList.remove("invalid"));
}

function showFieldError(field, message) {
  const el = document.querySelector(`[data-error-for="${field}"]`);
  if (el) el.textContent = message;
  const input = document.getElementById(field);
  if (input) input.classList.add("invalid");
}

// ===================== KIỂM TRA DỮ LIỆU =====================
function validate(data) {
  const errors = {};
  const namePattern = /^[A-Za-z0-9_]{3,30}$/;

  if (!data.sender) {
    errors.sender = "Vui lòng nhập người gửi";
  } else if (!namePattern.test(data.sender)) {
    errors.sender = "Chỉ gồm chữ, số, dấu _ (3-30 ký tự)";
  }

  if (!data.receiver) {
    errors.receiver = "Vui lòng nhập người nhận";
  } else if (!namePattern.test(data.receiver)) {
    errors.receiver = "Chỉ gồm chữ, số, dấu _ (3-30 ký tự)";
  } else if (data.receiver === data.sender) {
    errors.receiver = "Người nhận không được trùng người gửi";
  }

  if (data.amountRaw === "") {
    errors.amount = "Vui lòng nhập số tiền";
  } else if (!Number.isInteger(data.amount)) {
    errors.amount = "Số tiền phải là số nguyên";
  } else if (data.amount <= 0) {
    errors.amount = "Số tiền phải lớn hơn 0";
  } else if (data.amount > 1000000000) {
    errors.amount = "Số tiền tối đa 1.000.000.000";
  }

  if (data.content.length > 200) {
    errors.content = "Nội dung tối đa 200 ký tự";
  }

  return errors;
}

// ===================== GỬI DỮ LIỆU ĐẾN SERVER =====================
async function sendTransfer(payload) {
  if (USE_MOCK) {
    await new Promise((resolve) => setTimeout(resolve, 600)); // giả lập độ trễ mạng
    return { status: "success", message: "(Giả lập) Server đã nhận giao dịch" };
  }

  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  let data = {};
  try {
    data = await response.json();
  } catch (e) {
    // server không trả JSON, bỏ qua
  }

  if (!response.ok) {
    throw new Error(data.message || data.error || `Lỗi server (${response.status})`);
  }
  return data;
}

// ===================== XÁC NHẬN MẬT KHẨU =====================

const passwordModal = document.getElementById("password-modal");
const passwordInput = document.getElementById("confirm-password");
const passwordError = document.getElementById("password-error");
const confirmPasswordBtn = document.getElementById("confirm-password-btn");
const cancelPasswordBtn = document.getElementById("cancel-password");

let pendingPayload = null;

// Mở cửa sổ xác nhận mật khẩu
function openPasswordModal(payload) {
    pendingPayload = payload;

    passwordInput.value = "";
    passwordError.textContent = "";

    passwordModal.style.display = "flex";
    passwordInput.focus();
}

// Đóng cửa sổ xác nhận
function closePasswordModal() {
    passwordModal.style.display = "none";
    passwordInput.value = "";
    passwordError.textContent = "";
    pendingPayload = null;
}

// ===================== BƯỚC 1: KIỂM TRA THÔNG TIN =====================

form.addEventListener("submit", (event) => {
    event.preventDefault();

    hideAlert();
    clearErrors();
    resultBox.classList.add("hidden");

    const amountRaw = document.getElementById("amount").value.trim();

    const input = {
        sender: document.getElementById("sender").value.trim(),
        receiver: document.getElementById("receiver").value.trim(),
        amountRaw: amountRaw,
        amount: Number(amountRaw),
        currency: document.getElementById("currency").value,
        content: document.getElementById("content").value.trim(),
    };

    const errors = validate(input);

    if (Object.keys(errors).length > 0) {
        for (const field in errors) {
            showFieldError(field, errors[field]);
        }

        showAlert("Vui lòng kiểm tra lại thông tin", "error");
        return;
    }

    // Đóng gói dữ liệu giao dịch
    const payload = {
    transaction_id: generateTransactionId(),
    idempotency_key: crypto.randomUUID(),
    sender: input.sender,
    receiver: input.receiver,
    amount: input.amount,
    currency: input.currency,
    content: input.content || "Chuyen tien",
    timestamp: getTimestamp()
};
    // Hiện cửa sổ nhập lại mật khẩu
    openPasswordModal(payload);
});

// ===================== BƯỚC 2: GỬI GIAO DỊCH =====================

async function processTransfer() {
    if (!pendingPayload) {
        return;
    }

    const password = passwordInput.value;

    if (!password) {
        passwordError.textContent = "Vui lòng nhập mật khẩu.";
        return;
    }

    // Thêm mật khẩu vào request gửi Backend
    const requestPayload = {
        ...pendingPayload,
        password: password
    };

    confirmPasswordBtn.disabled = true;
    cancelPasswordBtn.disabled = true;
    submitBtn.disabled = true;

    confirmPasswordBtn.textContent = "Đang xác thực...";

    try {
        const result = await sendTransfer(requestPayload);

        if (!result.success || !result.transaction_id) {
            throw new Error(
                result.message || "Không thể xử lý giao dịch."
            );
        }

        console.log(
            "PHẢN HỒI BACKEND:",
            JSON.stringify(result, null, 2)
        );

        // Lưu thông tin giao dịch
        localStorage.setItem(
            "latest_transaction",
            JSON.stringify(result.transaction)
        );

        localStorage.setItem(
            "latest_encrypted_package",
            JSON.stringify(result.encrypted_transaction)
        );

        // Xóa mật khẩu khỏi ô nhập
        passwordInput.value = "";

        closePasswordModal();

        showAlert(
            result.message || "Giao dịch thành công.",
            "success"
        );

        resultJson.textContent = JSON.stringify(result, null, 2);
        resultBox.classList.remove("hidden");

        // Chuyển sang trang mã hóa AES + RSA
        window.location.href =
            "/encryption?transaction_id=" +
            encodeURIComponent(result.transaction_id);

    } catch (error) {
        passwordError.textContent = error.message;

    } finally {
        confirmPasswordBtn.disabled = false;
        cancelPasswordBtn.disabled = false;
        submitBtn.disabled = false;

        confirmPasswordBtn.textContent = "Xác nhận";
        submitBtn.textContent = "Xác nhận chuyển tiền";
    }
}

// Nhấn nút xác nhận mật khẩu
confirmPasswordBtn.addEventListener("click", processTransfer);

// Cho phép nhấn Enter để xác nhận
passwordInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
        processTransfer();
    }
});

// Nhấn hủy
cancelPasswordBtn.addEventListener("click", () => {
    closePasswordModal();
});

// Nhấn ra ngoài cửa sổ để đóng
passwordModal.addEventListener("click", (event) => {
    if (event.target === passwordModal) {
        closePasswordModal();
    }
});