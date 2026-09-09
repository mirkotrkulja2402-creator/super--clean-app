(() => {
    "use strict";

    const esc = (value) => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const apiCall = (url, options = {}) => {
        if (typeof api === "function") return api(url, options);
        return fetch(url, {
            ...options,
            credentials: "same-origin",
            headers: { "Content-Type": "application/json", ...(options.headers || {}) },
        }).then(async (response) => {
            const data = await response.json().catch(() => ({}));
            if (!response.ok) throw new Error(data.error || "Operacija nije uspjela.");
            return data;
        });
    };

    const money = (value) => `${Number(value || 0).toFixed(2)} KM`;
    const dateBs = (value) => {
        if (!value) return "—";
        const parts = String(value).slice(0, 10).split("-");
        return parts.length === 3 ? `${parts[2]}.${parts[1]}.${parts[0]}.` : String(value);
    };
    const dateTime = (value) => value ? new Intl.DateTimeFormat("bs-BA", {
        day: "2-digit", month: "2-digit", year: "numeric",
        hour: "2-digit", minute: "2-digit",
    }).format(new Date(value)) : "—";

    function permission(code) {
        return typeof hasPermission === "function" ? hasPermission(code) : false;
    }

    function addToolbarButton(id, label, icon, callback) {
        const toolbar = document.querySelector(".quick-toolbar");
        if (!toolbar || document.getElementById(id)) return;
        const button = document.createElement("button");
        button.id = id;
        button.type = "button";
        button.innerHTML = `${icon}<span>${esc(label)}</span>`;
        button.addEventListener("click", callback);
        toolbar.appendChild(button);
    }

    function addHomeCard(id, title, description, icon, callback) {
        const grid = document.querySelector(".home-grid");
        if (!grid || document.getElementById(id)) return;
        const button = document.createElement("button");
        button.id = id;
        button.className = "home-card ab-home-card";
        button.innerHTML = `<span class="home-icon">${icon}</span><strong>${esc(title)}</strong><small>${esc(description)}</small>`;
        button.addEventListener("click", callback);
        grid.appendChild(button);
    }

    function statusForJob(job) {
        if (job.status === "ASSIGNED") return ["🔵", "Dodijeljeno"];
        if (job.status === "COMPLETED") return ["🟢", "Završeno"];
        return ["🟡", "Nerutirano"];
    }

    function routeJobCode(job) {
        if (job.source_type === "ORDER") return `N-${String(job.order_number || "").padStart(3, "0")}`;
        return `R-${String(job.invoice_no || "").padStart(3, "0")}`;
    }

    function actionLabel(job) {
        return job.action_type === "DELIVERY" ? "DOSTAVA" : "PREUZIMANJE";
    }

    function routePage(data, vehicles) {
        const unrouted = data.filter((job) => job.status === "UNROUTED");
        const assigned = data.filter((job) => job.status === "ASSIGNED");
        const vehicleGroups = vehicles.map((vehicle) => ({
            vehicle,
            jobs: assigned.filter((job) => job.vehicle_id === vehicle.id)
                .sort((a, b) => Number(a.sequence_no || 9999) - Number(b.sequence_no || 9999)),
        }));

        const jobCard = (job, options = {}) => {
            const [icon, status] = statusForJob(job);
            const code = routeJobCode(job);
            const mapButton = Number.isFinite(Number(job.latitude)) && Number.isFinite(Number(job.longitude))
                ? `<button class="ab-small-button" data-route-nav="${esc(job.latitude)},${esc(job.longitude)}">🧭 Navigacija</button>`
                : `<span class="ab-no-location">⚠️ Nema GPS</span>`;
            return `
                <article class="ab-route-job">
                    <div class="ab-route-job-top">
                        <div>
                            <span class="ab-route-code">${esc(code)}</span>
                            <span class="ab-action ${job.action_type === "DELIVERY" ? "delivery" : "pickup"}">${actionLabel(job)}</span>
                        </div>
                        <span class="ab-status">${icon} ${esc(status)}</span>
                    </div>
                    <strong>${esc(job.customer_name || "Bez kupca")}</strong>
                    <span>📍 ${esc([job.address, job.city].filter(Boolean).join(", ") || "Adresa nije unesena")}</span>
                    ${job.phone ? `<span>📞 ${esc(job.phone)}</span>` : ""}
                    ${job.source_type === "ORDER" && job.planned_pickup_date
                        ? `<span>📅 Planirano: ${esc(dateBs(job.planned_pickup_date))}${job.pickup_time_from ? ` · ${esc(String(job.pickup_time_from).slice(0,5))}–${esc(String(job.pickup_time_to || "").slice(0,5))}` : ""}</span>`
                        : ""}
                    <div class="ab-job-actions">
                        ${options.assign ? vehicles.map((vehicle) => `<button class="ab-small-button ab-vehicle-button" data-route-assign="${esc(job.id)}" data-vehicle-id="${esc(vehicle.id)}">🚚 ${esc(vehicle.name)}</button>`).join("") : ""}
                        ${options.assigned ? `
                            <button class="ab-small-button" data-route-complete="${esc(job.id)}">✅ Završeno</button>
                            <button class="ab-small-button danger" data-route-not-driven="${esc(job.id)}">↩ Nije odvezeno</button>
                            ${mapButton}
                        ` : ""}
                    </div>
                </article>`;
        };

        return `
            <section class="page-panel ab-route-page">
                <div class="panel-heading">
                    <div><span class="eyebrow">OPERATIVA</span><h2>Ruta</h2></div>
                    <div class="ab-heading-actions">
                        ${permission("routes.manage") ? `<button class="compact-primary" id="ab-add-vehicle">➕ Vozilo</button>` : ""}
                        ${permission("admin.settings") ? `<button class="secondary-button" id="ab-memorandum">📄 Memorandum</button>` : ""}
                        <button class="secondary-button" id="ab-print-route">🖨️ Print ruta</button>
                    </div>
                </div>
                <div class="ab-route-summary">
                    <div><strong>${unrouted.length}</strong><span>Nerutirano</span></div>
                    <div><strong>${assigned.length}</strong><span>Na rutama</span></div>
                    <div><strong>${vehicles.length}</strong><span>Vozila</span></div>
                </div>
                <section class="ab-route-section">
                    <div class="ab-section-title"><h3>NERUTIRANO</h3><span>${unrouted.length}</span></div>
                    ${unrouted.length
                        ? unrouted.map((job) => jobCard(job, { assign: true })).join("")
                        : '<div class="empty-state">Nema nedodijeljenih vožnji.</div>'}
                </section>
                <section class="ab-route-section">
                    <div class="ab-section-title"><h3>VOZILA</h3></div>
                    ${vehicleGroups.map(({ vehicle, jobs }) => `
                        <article class="ab-vehicle-card">
                            <div class="ab-vehicle-heading">
                                <div><span>🚚</span><strong>${esc(vehicle.name)}</strong><small>${jobs.length} stanica</small></div>
                                <button class="secondary-button" data-route-optimize="${esc(vehicle.id)}" ${jobs.length < 2 ? "disabled" : ""}>⚡ Optimiziuj</button>
                            </div>
                            ${jobs.length
                                ? jobs.map((job, index) => `
                                    <div class="ab-stop">
                                        <span class="ab-stop-number">${index + 1}</span>
                                        ${jobCard(job, { assigned: true })}
                                        <div class="ab-reorder">
                                            <button class="ab-small-button" data-route-reorder="${esc(job.id)}" data-sequence="${Math.max(1, Number(job.sequence_no || 1) - 1)}">↑</button>
                                            <button class="ab-small-button" data-route-reorder="${esc(job.id)}" data-sequence="${Number(job.sequence_no || 1) + 1}">↓</button>
                                        </div>
                                    </div>
                                `).join("")
                                : '<div class="empty-state">Vozilo nema dodijeljenih vožnji.</div>'}
                        </article>
                    `).join("")}
                </section>
            </section>
        `;
    }

    async function printRoute() {
        try {
            const [routeData, vehicleData, memoData] = await Promise.all([
                apiCall("/api/routes"),
                apiCall("/api/routes/vehicles"),
                apiCall("/api/admin/memorandum"),
            ]);
            const activeJobs = routeData.routes || [];
            const vehicles = vehicleData.vehicles || [];
            const memo = memoData.memorandum || {};
            const groups = vehicles.map((vehicle) => ({
                vehicle,
                jobs: activeJobs.filter((job) => job.status === "ASSIGNED" && job.vehicle_id === vehicle.id)
                    .sort((a, b) => Number(a.sequence_no || 9999) - Number(b.sequence_no || 9999)),
            })).filter((group) => group.jobs.length);

            const body = groups.length
                ? groups.map((group) => `
                    <section class="ab-print-route-section">
                        <h3>${esc(group.vehicle.name)}</h3>
                        <ol>
                            ${group.jobs.map((job) => `
                                <li>
                                    <strong>${esc(routeJobCode(job))} · ${esc(actionLabel(job))}</strong>
                                    — ${esc(job.customer_name || "Bez kupca")}<br>
                                    ${esc([job.address, job.city].filter(Boolean).join(", ") || "Adresa nije unesena")}
                                    ${job.phone ? `<br>${esc(job.phone)}` : ""}
                                </li>
                            `).join("")}
                        </ol>
                    </section>
                `).join("")
                : "<p>Nema dodijeljenih vožnji.</p>";

            const frame = window.open("", "_blank", "noopener,noreferrer");
            if (!frame) {
                alert("Pregled štampe je blokiran. Dozvoli otvaranje prozora za štampu.");
                return;
            }
            frame.document.write(`<!doctype html><html lang="bs"><head><meta charset="utf-8">
                <title>Ruta</title><link rel="stylesheet" href="/ab-enhancements.css"></head>
                <body><main class="ab-print-page"><header class="ab-print-header">
                <img src="/logo.jpg" alt="Super Clean"><div><h1>${esc(memo.companyName || "SUPER CLEAN TEPIH SERVIS")}</h1>
                <p>${esc([memo.address, memo.phone].filter(Boolean).join(" · "))}</p></div></header>
                <h2>Ruta</h2>${body}</main><script>window.onload=()=>window.print();</script></body></html>`);
            frame.document.close();
        } catch (error) {
            alert(error.message);
        }
    }

    async function openRoute() {
        if (!permission("routes.view")) {
            alert("Nemaš dozvolu za Rutu.");
            return;
        }
        try {
            const [routeData, vehicleData] = await Promise.all([
                apiCall("/api/routes"),
                apiCall("/api/routes/vehicles"),
            ]);
            const content = document.getElementById("page-content");
            content.innerHTML = routePage(routeData.routes || [], vehicleData.vehicles || []);
            bindRouteActions();
        } catch (error) {
            alert(error.message);
        }
    }

    async function bindRouteActions() {
        document.querySelectorAll("[data-route-assign]").forEach((button) => {
            button.addEventListener("click", async () => {
                try {
                    await apiCall(`/api/routes/jobs/${button.dataset.routeAssign}/assign`, {
                        method: "PATCH",
                        body: JSON.stringify({ vehicleId: button.dataset.vehicleId }),
                    });
                    await openRoute();
                } catch (error) { alert(error.message); }
            });
        });

        document.querySelectorAll("[data-route-complete]").forEach((button) => {
            button.addEventListener("click", async () => {
                try {
                    await apiCall(`/api/routes/jobs/${button.dataset.routeComplete}/complete`, { method: "PATCH" });
                    await openRoute();
                } catch (error) { alert(error.message); }
            });
        });

        document.querySelectorAll("[data-route-not-driven]").forEach((button) => {
            button.addEventListener("click", async () => {
                if (!confirm("Vratiti ovu vožnju u Nerutirano? Pokušaj će ostati u istoriji.")) return;
                try {
                    await apiCall(`/api/routes/jobs/${button.dataset.routeNotDriven}/not-driven`, { method: "PATCH" });
                    await openRoute();
                } catch (error) { alert(error.message); }
            });
        });

        document.querySelectorAll("[data-route-reorder]").forEach((button) => {
            button.addEventListener("click", async () => {
                try {
                    await apiCall(`/api/routes/jobs/${button.dataset.routeReorder}/reorder`, {
                        method: "PATCH",
                        body: JSON.stringify({ sequence: Number(button.dataset.sequence) }),
                    });
                    await openRoute();
                } catch (error) { alert(error.message); }
            });
        });

        document.querySelectorAll("[data-route-optimize]").forEach((button) => {
            button.addEventListener("click", async () => {
                try {
                    await apiCall(`/api/routes/optimize/${button.dataset.routeOptimize}`, { method: "POST" });
                    await openRoute();
                } catch (error) { alert(error.message); }
            });
        });

        document.querySelectorAll("[data-route-nav]").forEach((button) => {
            button.addEventListener("click", () => {
                const [lat, lng] = button.dataset.routeNav.split(",");
                if (typeof openNavigation === "function") {
                    openNavigation(Number(lat), Number(lng));
                } else {
                    window.open(`https://www.google.com/maps/dir/?api=1&destination=${encodeURIComponent(`${lat},${lng}`)}`, "_blank", "noopener,noreferrer");
                }
            });
        });

        document.getElementById("ab-add-vehicle")?.addEventListener("click", async () => {
            const name = prompt("Naziv vozila:", `Vozilo ${(await apiCall("/api/routes/vehicles")).vehicles.length + 1}`);
            if (!name) return;
            try {
                await apiCall("/api/routes/vehicles", { method: "POST", body: JSON.stringify({ name }) });
                await openRoute();
            } catch (error) { alert(error.message); }
        });

        document.getElementById("ab-memorandum")?.addEventListener("click", openMemorandumSettings);
        document.getElementById("ab-print-route")?.addEventListener("click", printRoute);
    }

    function cashierPage(invoices, filter = "all") {
        const filtered = invoices.filter((invoice) => {
            if (filter === "unpaid") return !invoice.paid && invoice.status !== "CANCELLED";
            if (filter === "paid") return invoice.paid;
            if (filter === "cash") return invoice.paid && invoice.payment_method === "cash";
            if (filter === "card") return invoice.paid && invoice.payment_method === "card";
            if (filter === "bank") return invoice.paid && invoice.payment_method === "bank";
            if (filter === "cancelled") return invoice.status === "CANCELLED";
            return true;
        });
        const row = (invoice) => `
            <article class="ab-cash-row">
                <div>
                    <div><span class="ab-route-code">R-${String(invoice.invoice_no).padStart(3, "0")}</span>
                    <span class="ab-status">${invoice.status === "CANCELLED" ? "🔴 Storniran" : invoice.paid ? "🟢 Plaćen" : "⚪ Nije naplaćen"}</span></div>
                    <strong>${esc(invoice.customer_name || "Bez kupca")}</strong>
                    <small>Račun izdat: ${esc(dateTime(invoice.issued_at))}</small>
                    ${invoice.paid_at ? `<small>Naplaćeno: ${esc(dateTime(invoice.paid_at))} · ${esc(invoice.paid_by_name || "")}</small>` : ""}
                </div>
                <div class="ab-cash-actions">
                    ${invoice.paid
                        ? `<span class="ab-payment-chip">${esc(invoice.payment_method || "")}</span>
                           ${permission("cashier.edit") ? `<button class="ab-small-button danger" data-unpay="${esc(invoice.id)}">↩ Poništi naplatu</button>` : ""}`
                        : permission("cashier.edit") && invoice.status !== "CANCELLED"
                            ? `<button class="ab-small-button" data-pay="${esc(invoice.id)}" data-method="cash">💵 Gotovina</button>
                               <button class="ab-small-button" data-pay="${esc(invoice.id)}" data-method="card">💳 Kartica</button>
                               <button class="ab-small-button" data-pay="${esc(invoice.id)}" data-method="bank">🏦 Transakcijski račun</button>`
                            : ""}
                </div>
            </article>`;
        return `
            <section class="page-panel ab-cashier-page">
                <div class="panel-heading"><div><span class="eyebrow">NAPLATA</span><h2>Blagajna</h2></div></div>
                <div class="ab-filter-row">
                    ${[
                        ["all", "Svi"], ["unpaid", "Nenaplaćeni"], ["paid", "Naplaćeni"],
                        ["cash", "Gotovina"], ["card", "Kartica"], ["bank", "Transakcijski račun"], ["cancelled", "Stornirani"],
                    ].map(([key, label]) => `<button class="${filter === key ? "active" : ""}" data-cash-filter="${key}">${label}</button>`).join("")}
                </div>
                <div class="ab-cash-list">${filtered.map(row).join("") || '<div class="empty-state">Nema računa za izabrani filter.</div>'}</div>
            </section>
        `;
    }

    async function openCashier(filter = "all") {
        if (!permission("cashier.view")) {
            alert("Nemaš dozvolu za Blagajnu.");
            return;
        }
        try {
            const data = await apiCall("/api/cashier");
            document.getElementById("page-content").innerHTML = cashierPage(data.invoices || [], filter);
            bindCashierActions(filter);
        } catch (error) { alert(error.message); }
    }

    function bindCashierActions(filter) {
        document.querySelectorAll("[data-cash-filter]").forEach((button) => {
            button.addEventListener("click", () => openCashier(button.dataset.cashFilter));
        });
        document.querySelectorAll("[data-pay]").forEach((button) => {
            button.addEventListener("click", async () => {
                try {
                    await apiCall(`/api/cashier/${button.dataset.pay}/pay`, {
                        method: "POST",
                        body: JSON.stringify({ paymentMethod: button.dataset.method }),
                    });
                    await openCashier(filter);
                } catch (error) { alert(error.message); }
            });
        });
        document.querySelectorAll("[data-unpay]").forEach((button) => {
            button.addEventListener("click", async () => {
                if (!confirm("Poništiti evidenciju naplate?")) return;
                try {
                    await apiCall(`/api/cashier/${button.dataset.unpay}/unpay`, { method: "PATCH" });
                    await openCashier(filter);
                } catch (error) { alert(error.message); }
            });
        });
    }

    async function openMemorandumSettings() {
        if (!permission("admin.settings")) {
            alert("Nemaš dozvolu za podešavanje memoranduma.");
            return;
        }
        try {
            const data = await apiCall("/api/admin/memorandum");
            const m = data.memorandum || {};
            const c = data.baseCoordinates || {};
            const html = `
                <div class="ab-modal-backdrop">
                    <section class="ab-modal">
                        <button class="ab-modal-close" id="ab-close-memo">×</button>
                        <h2>Memorandum firme</h2>
                        <p>Logo ostaje postojeći Super Clean logo. Ovdje se mijenjaju samo podaci memoranduma i baza za optimizaciju rute.</p>
                        <form id="ab-memo-form">
                            <label>Naziv firme<input name="companyName" value="${esc(m.companyName || "")}" required></label>
                            <label>Adresa<input name="address" value="${esc(m.address || "")}"></label>
                            <label>Telefon<input name="phone" value="${esc(m.phone || "")}"></label>
                            <label>E-mail<input name="email" value="${esc(m.email || "")}"></label>
                            <label>Web<input name="website" value="${esc(m.website || "")}"></label>
                            <div class="ab-two-col">
                                <label>GPS baza – širina<input name="baseLatitude" type="number" step="any" value="${c.latitude ?? ""}"></label>
                                <label>GPS baza – dužina<input name="baseLongitude" type="number" step="any" value="${c.longitude ?? ""}"></label>
                            </div>
                            <button class="primary-button">Sačuvaj</button>
                        </form>
                    </section>
                </div>`;
            document.getElementById("modal-root").innerHTML = html;
            document.getElementById("ab-close-memo").addEventListener("click", () => document.getElementById("modal-root").innerHTML = "");
            document.getElementById("ab-memo-form").addEventListener("submit", async (event) => {
                event.preventDefault();
                const form = event.currentTarget;
                try {
                    await apiCall("/api/admin/memorandum", {
                        method: "PUT",
                        body: JSON.stringify(Object.fromEntries(new FormData(form).entries())),
                    });
                    document.getElementById("modal-root").innerHTML = "";
                    alert("Memorandum je sačuvan.");
                } catch (error) { alert(error.message); }
            });
        } catch (error) { alert(error.message); }
    }

    async function printMemorandum(title, bodyHtml) {
        try {
            const data = await apiCall("/api/admin/memorandum");
            const memo = data.memorandum || {};
            const frame = window.open("", "_blank", "noopener,noreferrer");
            if (!frame) {
                alert("Pregled štampe je blokiran. Dozvoli otvaranje prozora za štampu.");
                return;
            }
            frame.document.write(`<!doctype html><html lang="bs"><head><meta charset="utf-8">
                <title>${esc(title)}</title><link rel="stylesheet" href="/ab-enhancements.css"></head>
                <body><main class="ab-print-page"><header class="ab-print-header">
                <img src="/logo.jpg" alt="Super Clean"><div><h1>${esc(memo.companyName || "SUPER CLEAN TEPIH SERVIS")}</h1>
                <p>${esc([memo.address, memo.phone, memo.email, memo.website].filter(Boolean).join(" · "))}</p></div></header>
                <h2>${esc(title)}</h2>${bodyHtml}</main><script>window.onload=()=>window.print();</script></body></html>`);
            frame.document.close();
        } catch (error) {
            alert(error.message);
        }
    }

    function injectNavigation() {
        if (!document.querySelector(".mobile-app")) return;
        if (permission("routes.view")) {
            addToolbarButton("ab-route-button", "Ruta", "🚚", openRoute);
            addHomeCard("ab-route-card", "Ruta", "Nerutirano i vozila", "🚚", openRoute);
        }
        if (permission("cashier.view")) {
            addToolbarButton("ab-cashier-button", "Blagajna", "💳", () => openCashier());
            addHomeCard("ab-cashier-card", "Blagajna", "Naplata računa", "💳", () => openCashier());
        }
        if (permission("admin.settings")) {
            addToolbarButton("ab-memo-button", "Memorandum", "📄", openMemorandumSettings);
        }
    }

    const observer = new MutationObserver(() => injectNavigation());
    observer.observe(document.documentElement, { childList: true, subtree: true });
    window.setInterval(injectNavigation, 1000);
    window.SuperCleanAB = { openRoute, openCashier, openMemorandumSettings, printMemorandum };
})();
