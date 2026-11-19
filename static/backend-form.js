(() => {
    // Short names of the credential modes, as the dialog says them.
    const MODE_NAMES = {
        shared: "shared",
        per_user: "per user",
        oauth: "OAuth",
        passthrough: "passthrough",
    };

    // Saving a backend with another credential mode than the stored one asks
    // first: the dialog says what the switch deletes, and the request goes out
    // with `confirm_mode_change=yes` only after a confirm.
    document.addEventListener("htmx:confirm", (evt) => {
        const form = evt.detail.elt;
        if (!(form instanceof HTMLFormElement) || !form.dataset.storedMode) {
            return;
        }
        const confirmed = form.elements.namedItem("confirm_mode_change");
        const select = form.elements.namedItem("credential_mode");
        const dialog = document.getElementById("mode-change-dialog");
        if (!confirmed || !select || !dialog) {
            return;
        }
        confirmed.value = "";
        if (select.value === form.dataset.storedMode) {
            return;
        }
        evt.preventDefault();
        const label = dialog.querySelector("[data-new-mode]");
        if (label) {
            label.textContent = MODE_NAMES[select.value] ?? select.value;
        }
        // Handlers are assigned, not added, so a second open replaces them.
        dialog.querySelector("[data-mode-cancel]").onclick = () => dialog.close();
        dialog.querySelector("[data-mode-confirm]").onclick = () => {
            confirmed.value = "yes";
            dialog.close();
            evt.detail.issueRequest(true);
        };
        dialog.showModal();
    });
})();
