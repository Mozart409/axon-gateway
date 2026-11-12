(() => {
    const copyButton = document.getElementById("copy-mcp-url");
    if (!copyButton) {
        return;
    }

    const feedback = document.getElementById("copy-mcp-url-feedback");
    copyButton.addEventListener("click", async () => {
        const mcpUrl = copyButton.dataset.url ?? "";

        try {
            await navigator.clipboard.writeText(mcpUrl);
            if (feedback) {
                feedback.textContent = "Copied MCP server URL.";
            }
        } catch (_error) {
            if (feedback) {
                feedback.textContent = "Copy failed. Copy the URL manually.";
            }
        }
    });
})();
