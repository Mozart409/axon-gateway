(() => {
    const copy = async (value, feedback, done) => {
        try {
            await navigator.clipboard.writeText(value);
            if (feedback) {
                feedback.textContent = done;
            }
        } catch (_error) {
            if (feedback) {
                feedback.textContent = "Copy failed. Copy the value manually.";
            }
        }
    };

    // The MCP URL on the landing page and the overview.
    const copyButton = document.getElementById("copy-mcp-url");
    if (copyButton) {
        const feedback = document.getElementById("copy-mcp-url-feedback");
        copyButton.addEventListener("click", () =>
            copy(copyButton.dataset.url ?? "", feedback, "Copied MCP server URL."),
        );
    }

    // Any other button with `data-copy`, reporting into `#copy-feedback`.
    const feedback = document.getElementById("copy-feedback");
    for (const button of document.querySelectorAll("[data-copy]")) {
        button.addEventListener("click", () =>
            copy(button.dataset.copy ?? "", feedback, "Copied."),
        );
    }
})();
