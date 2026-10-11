
const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.disable("x-powered-by");

// Serve the existing frontend.
app.use(express.static(path.join(__dirname, "public")));

// Parse JSON with a size limit.
app.use(express.json({ limit: "10kb" }));

// Consistent response format for every verdict.
function createVerdict(
    status,
    riskScore,
    threatCategory,
    explanation,
    extra = {}
) {
    return {
        status,
        decision: status,
        riskScore,
        threatCategory,
        rationale: explanation,
        explanation,
        ...extra
    };
}

// Detect suspicious instructions before processing a banking request.
function detectPromptInjection(text) {
    const patterns = [
        /ignore\s+(all\s+)?(previous|prior|system|security)\s+instructions?/i,
        /ignore\s+all\s+security\s+rules/i,
        /disregard\s+(all\s+)?instructions?/i,
        /bypass\s+(the\s+)?(security|safety|firewall|verification|authentication|checks?)/i,
        /override\s+(the\s+)?(system|security|safety|banking)\s+(prompt|policy|rules?)/i,
        /reveal\s+(your\s+)?(system\s+prompt|secret|confidential\s+data)/i,
        /disable\s+(security|safety|guardrails|firewall)/i,
        /act\s+as\s+(an?\s+)?(administrator|system|unrestricted\s+ai)/i,
        /developer\s+mode/i,
        /\bjailbreak\b/i,
        /forget\s+your\s+(rules|instructions|restrictions)/i,
        /do\s+not\s+follow\s+(the\s+)?(security|safety)\s+rules/i
    ];

    return patterns.some(pattern => pattern.test(text));
}

// Safely inspect a banking request.
function checkRequest(userRequest, amount, recipient) {
    if (
        typeof userRequest !== "string" ||
        userRequest.trim().length === 0
    ) {
        return createVerdict(
            "BLOCKED",
            100,
            "INVALID_REQUEST",
            "A non-empty banking request is required."
        );
    }

    if (userRequest.length > 2000) {
        return createVerdict(
            "BLOCKED",
            90,
            "REQUEST_TOO_LONG",
            "The request exceeds the permitted length."
        );
    }

    const request = userRequest.trim();
    const normalized = request.toLowerCase();

    // Inspect the recipient too, because it is untrusted input.
    const recipientText =
        typeof recipient === "string" ? recipient : "";

    if (detectPromptInjection(`${request}\n${recipientText}`)) {
        return createVerdict(
            "BLOCKED",
            100,
            "PROMPT_INJECTION",
            "The request contains instructions that may attempt to bypass security controls."
        );
    }

    // Identify explicitly supported banking operations.
    const transferIntent =
        /\b(transfer|send|pay|payment|remit)\b/i.test(normalized);

    const balanceIntent =
        /\b(balance|available funds|how much money)\b/i.test(normalized);

    // Do not guess when the request mixes different operations.
    if (transferIntent && balanceIntent) {
        return createVerdict(
            "BLOCKED",
            85,
            "AMBIGUOUS_REQUEST",
            "The request combines different banking operations. Submit one clear operation at a time."
        );
    }

    // Mock balance checks only. No account is accessed.
    if (balanceIntent && !transferIntent) {
        if (
            !/\b(check|show|tell|what|display|view|my|account|available)\b/i.test(normalized)
        ) {
            return createVerdict(
                "BLOCKED",
                70,
                "AMBIGUOUS_REQUEST",
                "Please clarify the balance-check request."
            );
        }

        return createVerdict(
            "APPROVED",
            5,
            "NONE_DETECTED",
            "The mock balance-check request passed basic security checks. No real account was accessed.",
            {
                requestType: "BALANCE_CHECK",
                mockResult: {
                    executed: false,
                    balance: null,
                    message: "No account balance is connected to this prototype."
                }
            }
        );
    }

    // Never approve an unknown operation by default.
    if (!transferIntent) {
        return createVerdict(
            "BLOCKED",
            70,
            "UNSUPPORTED_REQUEST",
            "The request does not match a supported banking operation."
        );
    }

    // A transfer must contain a valid positive amount.
    const numericAmount =
        typeof amount === "number" ||
        (typeof amount === "string" && amount.trim() !== "")
            ? Number(amount)
            : NaN;

    if (!Number.isFinite(numericAmount) || numericAmount <= 0) {
        return createVerdict(
            "BLOCKED",
            100,
            "INVALID_AMOUNT",
            "The transfer amount must be a valid positive number."
        );
    }

    if (numericAmount > 100000) {
        return createVerdict(
            "BLOCKED",
            90,
            "HIGH_VALUE_TRANSFER",
            "The amount exceeds ₹1,00,000 and requires additional verification."
        );
    }

    // Validate the recipient's format and length.
    if (
        typeof recipient !== "string" ||
        recipient.trim().length === 0
    ) {
        return createVerdict(
            "BLOCKED",
            100,
            "MISSING_RECIPIENT",
            "A recipient is required for a transfer."
        );
    }

    const cleanRecipient = recipient.trim();

    if (
        cleanRecipient.length > 100 ||
        !/^[\p{L}\p{N}][\p{L}\p{N} .'-]*$/u.test(cleanRecipient)
    ) {
        return createVerdict(
            "BLOCKED",
            100,
            "INVALID_RECIPIENT",
            "The recipient contains invalid characters or exceeds the permitted length."
        );
    }

    // Require the request to express an amount and recipient.
    const mentionsAmount =
        /\b\d+(?:\.\d{1,2})?\b/.test(normalized) ||
        /\b(amount|rupees|rupee|inr|rs\.?|₹)\b/i.test(normalized);

    if (!mentionsAmount) {
        return createVerdict(
            "BLOCKED",
            70,
            "AMBIGUOUS_REQUEST",
            "The request must clearly specify the transfer amount."
        );
    }

    // This is validation only—not execution or authorization of a real transfer.
    return createVerdict(
        "APPROVED",
        10,
        "NONE_DETECTED",
        "The mock transfer passed the prototype's basic security checks. No money was transferred.",
        {
            requestType: "MOCK_TRANSFER",
            mockResult: {
                amount: numericAmount,
                currency: "INR",
                recipient: cleanRecipient,
                executed: false,
                message: "Validated only. No real financial transaction was executed."
            }
        }
    );
}

// API endpoint.
app.post("/api/check", (req, res) => {
    const body = req.body;

    if (
        !body ||
        typeof body !== "object" ||
        Array.isArray(body)
    ) {
        return res.status(400).json(
            createVerdict(
                "BLOCKED",
                100,
                "INVALID_REQUEST",
                "The request body must be a JSON object."
            )
        );
    }

    const { userRequest, amount, recipient } = body;

    const verdict = checkRequest(userRequest, amount, recipient);

    return res.status(200).json(verdict);
});

// Return structured errors for malformed JSON.
app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }

    if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
        return res.status(400).json(
            createVerdict(
                "BLOCKED",
                100,
                "INVALID_JSON",
                "The request body contains invalid JSON."
            )
        );
    }

    if (err.type === "entity.too.large") {
        return res.status(413).json(
            createVerdict(
                "BLOCKED",
                90,
                "REQUEST_TOO_LARGE",
                "The request body exceeds the permitted size."
            )
        );
    }

    console.error("BankSim server error:", err.message);

    return res.status(500).json(
        createVerdict(
            "BLOCKED",
            100,
            "INTERNAL_ERROR",
            "The server could not safely process the request."
        )
    );
});

app.listen(PORT, "0.0.0.0", () => {
    console.log(`BankSim server running on port ${PORT}`);
});
