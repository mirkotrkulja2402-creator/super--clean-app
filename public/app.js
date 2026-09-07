const app = document.getElementById("app");

const mainMenu = [
    ["➕", "Nova narudžba", "Brzo zaprimanje tepiha", "orders.view"],
    ["👥", "Kupci", "Kupci i kontakt podaci", "customers.view"],
    ["📋", "Narudžbe", "Pregled i statusi", "orders.view"],
    ["💰", "Cjenovnik", "Usluge i cijene", "pricing.view"],
    ["🏷️", "Etikete", "Štampanje etiketa", "labels.view"],
    ["📷", "QR kod", "Kreiranje i skeniranje", "qr.view"],
    ["🧾", "Računi", "Računi i fakture", "invoices.view"],
    ["📊", "Izvještaji", "Pregled poslovanja", "reports.view"],
];

const permissionGroups = [
    ["Kupci", [
        ["customers.view", "Pregled kupaca"],
        ["customers.create", "Dodavanje kupaca"],
        ["customers.edit", "Izmjena kupaca"],
        ["customers.delete", "Brisanje kupaca"],
    ]],
    ["Narudžbe", [
        ["orders.view", "Pregled narudžbi"],
        ["orders.create", "Dodavanje narudžbi"],
        ["orders.edit", "Izmjena narudžbi"],
        ["orders.delete", "Brisanje narudžbi"],
    ]],
    ["Cjenovnik", [
        ["pricing.view", "Pregled cjenovnika"],
        ["pricing.edit", "Izmjena cjenovnika"],
    ]],
    ["Etikete i QR", [
        ["labels.view", "Pregled etiketa"],
        ["labels.print", "Štampanje etiketa"],
        ["qr.view", "Pregled QR kodova"],
        ["qr.create", "Kreiranje QR kodova"],
    ]],
    ["Računi", [
        ["invoices.view", "Pregled računa"],
        ["invoices.create", "Kreiranje računa"],
        ["invoices.edit", "Izmjena računa"],
        ["invoices.print", "Štampanje računa"],
    ]],
    ["Izvještaji", [
        ["reports.view", "Pregled izvještaja"],
        ["reports.export", "Izvoz izvještaja"],
    ]],
    ["Excel", [
        ["excel.import", "Uvoz Excel podataka"],
        ["excel.export", "Izvoz Excel podataka"],
    ]],
    ["Administracija", [
        ["admin.users", "Upravljanje korisnicima"],
        ["admin.roles", "Upravljanje ulogama i dozvolama"],
        ["admin.settings", "Podešavanja aplikacije"],
    ]],
];

let currentUser = null;
let rolesData = [];
let permissionsData = [];

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function hasPermission(code) {
    return currentUser?.role === "ADMIN" || currentUser?.permissions?.includes(code);
}

function loginView(error = "") {
    app.innerHTML = `
        <main class="login-page">
            <section class="login-card">
                <img class="login-logo" src="/logo.jpg" alt="Super Clean logo">
                <h1>Super Clean</h1>
                <p>Banja Luka · poslovna aplikacija</p>
                <div id="login-error" class="${error ? "error" : "error hidden"}">${escapeHtml(error)}</div>
                <form id="login-form">
                    <label>Korisničko ime
                        <input name="username" autocomplete="username" required autofocus>
                    </label>
                    <label>Lozinka
                        <input name="password" type="password" autocomplete="current-password" required>
                    </label>
                    <button class="primary-button" id="login-button">Prijavi se</button>
                </form>
            </section>
        </main>
    `;
    document.getElementById("login-form").addEventListener("submit", handleLogin);
}

function dashboardView(user) {
    currentUser = user;
    app.innerHTML = `
        <div class="mobile-app">
            <header class="mobile-header">
                <button class="icon-button" id="menu-toggle" aria-label="Meni">☰</button>
                <div class="header-brand">
                    <strong>SUPER CLEAN</strong>
                    <span>Banja Luka</span>
                </div>
                <button class="icon-button" id="user-menu" aria-label="Korisnik">👤</button>
            </header>

            <div class="mobile-search">
                <span>🔎</span>
                <input id="global-search" placeholder="Pretraži..." aria-label="Pretraži">
            </div>

            <div class="quick-toolbar" aria-label="Brze radnje">
                <button data-action="add">➕<span>Dodaj</span></button>
                <button data-action="remove">🗑️<span>Ukloni</span></button>
                <button data-action="print">🖨️<span>Print</span></button>
                <button data-action="pdf">📄<span>PDF</span></button>
                <button data-action="search">🔎<span>Pretraga</span></button>
                <button id="more-actions">⋯<span>Više</span></button>
            </div>

            <main id="page-content">${homeContent()}</main>

            <nav class="bottom-nav">
                <button data-page="home">🏠<span>Početna</span></button>
                ${hasPermission("orders.view") ? '<button data-page="orders">📋<span>Narudžbe</span></button>' : ""}
                ${hasPermission("customers.view") ? '<button data-page="customers">👥<span>Kupci</span></button>' : ""}
                ${user.role === "ADMIN" ? '<button data-page="admin">⚙️<span>Admin</span></button>' : ""}
            </nav>

            <div id="drawer" class="drawer hidden"></div>
            <div id="modal-root"></div>
            <input id="excel-file" type="file" accept=".xlsx,.xls,.csv" class="hidden">
        </div>
    `;

    bindDashboard();
    loadDashboard();
}

function homeContent() {
    const cards = mainMenu
        .filter(([, , , permission]) => hasPermission(permission))
        .map(([icon, title, description]) => `
            <button class="home-card" data-page-label="${escapeHtml(title)}">
                <span class="home-icon">${icon}</span>
                <strong>${escapeHtml(title)}</strong>
                <small>${escapeHtml(description)}</small>
            </button>
        `)
        .join("");

    return `
        <section class="welcome">
            <div>
                <span>Dobro došao</span>
                <h1>${escapeHtml(currentUser.firstName)} 👋</h1>
            </div>
            <span class="role-badge">${escapeHtml(currentUser.roleName || currentUser.role)}</span>
        </section>

        <section class="dashboard-section">
            <div class="dashboard-section-heading">
                <div>
                    <span class="eyebrow">DANAS</span>
                    <h2>Pregled dana</h2>
                </div>
                <span id="dashboard-date" class="dashboard-date"></span>
            </div>
            <div id="dashboard-summary" class="dashboard-summary">
                <div class="dashboard-loading">Učitavam pregled...</div>
            </div>
        </section>

        <section class="dashboard-section" id="dashboard-warnings-section">
            <div class="dashboard-section-heading">
                <div>
                    <span class="eyebrow">KONTROLA</span>
                    <h2>Upozorenja</h2>
                </div>
            </div>
            <div id="dashboard-warnings">
                <div class="dashboard-loading">Provjeravam podatke...</div>
            </div>
        </section>

        <button class="new-order" data-page-label="Nova narudžba">
            <span>➕</span>
            <div><strong>NOVA NARUDŽBA</strong><small>Unesi novi prijem tepiha</small></div>
            <b>›</b>
        </button>
        <section class="home-grid">${cards}</section>
    `;
}

function dashboardSummaryContent(summary) {
    const cards = [
        hasPermission("orders.view") ? ["📋", "Narudžbe", summary.orderCount, ""] : null,
        hasPermission("orders.view") ? ["🧼", "Tepisi", summary.carpetCount, ""] : null,
        hasPermission("invoices.view") ? ["🧾", "Fakturisano", summary.invoicedCount, formatKm(summary.invoicedTotal) + " KM"] : null,
        hasPermission("orders.view") ? ["🚚", "Dostava", "", formatKm(summary.deliveryTotal) + " KM"] : null,
        hasPermission("customers.view") ? ["👥", "Novi kupci", summary.newCustomerCount, ""] : null,
    ].filter(Boolean);

    return cards.length
        ? cards.map(([icon, label, value, detail]) => `
            <article class="dashboard-stat">
                <span class="dashboard-stat-icon">${icon}</span>
                <div>
                    <small>${label}</small>
                    <strong>${value === "" ? detail : value}</strong>
                    ${value !== "" && detail ? `<span>${detail}</span>` : ""}
                </div>
            </article>
        `).join("")
        : '<div class="dashboard-loading">Nema dostupnih podataka za tvoje dozvole.</div>';
}

function dashboardWarningsContent(warnings) {
    if (!warnings.length) {
        return `
            <div class="dashboard-ok">
                <span>✅</span>
                <div><strong>Sve je uredno</strong><small>Nema otvorenih upozorenja za provjerene podatke.</small></div>
            </div>
        `;
    }

    return warnings.map((warning) => `
        <button class="dashboard-warning" data-warning-page="${escapeHtml(warning.page)}">
            <span class="dashboard-warning-icon">⚠️</span>
            <span>
                <strong>${escapeHtml(warning.label)}</strong>
                <small>${escapeHtml(warning.description)}</small>
            </span>
            <b>${warning.count} ›</b>
        </button>
    `).join("");
}

async function loadDashboard() {
    const summaryBox = document.getElementById("dashboard-summary");
    const warningsBox = document.getElementById("dashboard-warnings");
    if (!summaryBox || !warningsBox) return;

    try {
        const data = await api("/api/dashboard/summary");
        summaryBox.innerHTML = dashboardSummaryContent(data.summary);
        warningsBox.innerHTML = dashboardWarningsContent(data.warnings);
        const date = new Date(`${data.date}T12:00:00`);
        document.getElementById("dashboard-date").textContent = new Intl.DateTimeFormat("bs-BA", {
            day: "2-digit",
            month: "2-digit",
            year: "numeric",
        }).format(date);

        warningsBox.querySelectorAll("[data-warning-page]").forEach((button) => {
            button.addEventListener("click", () => navigate(button.dataset.warningPage));
        });
    } catch (error) {
        summaryBox.innerHTML = `<div class="error">${escapeHtml(error.message)}</div>`;
        warningsBox.innerHTML = `
            <div class="dashboard-ok">
                <span>⚠️</span>
                <div><strong>Pregled nije dostupan</strong><small>Pokušaj ponovo kasnije.</small></div>
            </div>
        `;
    }
}


function formatKm(value) {
    return Number(value || 0).toFixed(2);
}

function formatDateBs(value) {
    if (!value) return "";
    const parts = String(value).split("-");
    return parts.length === 3 ? `${parts[2]}.${parts[1]}.${parts[0]}.` : String(value);
}

function invoiceNumber(order) {
    const year = String(order.invoiceIssuedAt || order.orderDate || new Date().toISOString().slice(0, 10)).slice(2, 4);
    const sequence = order.invoiceNumber || order.orderNumber;
    return `1/${year}-${String(sequence).padStart(5, "0")}`;
}

function invoiceStatusLabel(order) {
    if (order.invoiceStatus === "CANCELLED") return "STORNIRANO";
    if (order.invoiceStatus === "INVOICED") return "FAKTURISANO";
    return "U PRIPREMI";
}

function invoiceStatusClass(order) {
    if (order.invoiceStatus === "CANCELLED") return "invoice-status-cancelled";
    if (order.invoiceStatus === "INVOICED") return "invoice-status-invoiced";
    return "invoice-status-preparing";
}

function paymentMethodLabel(method) {
    if (method === "bank") return "ŽIRALNO";
    if (method === "card") return "KARTIČNO";
    return "GOTOVINSKI";
}

function invoiceContent(order, items) {

    const itemsTotal = items.reduce((sum, item) => sum + Number(item.total || 0), 0);
    const deliveryPrice = Number(order.deliveryPrice || 0);
    const total = Number((itemsTotal + deliveryPrice).toFixed(2));
    const paymentMethod = order.invoicePaymentMethod || "cash";
    const saved = order.invoiceStatus === "INVOICED";
    const cancelled = order.invoiceStatus === "CANCELLED";

    const rows = items.map((item, index) => {
        const dimension = item.unit === "m2"
            ? `${item.lengthM} × ${item.widthM} m`
            : `${item.quantity} kom.`;
        const quantity = item.unit === "m2"
            ? Number(item.areaM2 || 0).toFixed(2)
            : Number(item.quantity || 0).toFixed(2);

        return `
            <tr>
                <td>${index + 1}</td>
                <td>
                    <strong>${escapeHtml(item.serviceName)}</strong>
                    ${item.note ? `<small>${escapeHtml(item.note)}</small>` : ""}
                </td>
                <td>${escapeHtml(dimension)}</td>
                <td class="text-right">${escapeHtml(quantity)}</td>
                <td>${item.unit === "m2" ? "m²" : "kom."}</td>
                <td class="text-right">${formatKm(item.unitPrice)} KM</td>
                <td class="text-right"><strong>${formatKm(item.total)} KM</strong></td>
            </tr>
        `;
    }).join("");

    const deliveryRow = deliveryPrice > 0 ? `
        <tr>
            <td>${items.length + 1}</td>
            <td><strong>Dostava</strong></td>
            <td>—</td>
            <td class="text-right">1</td>
            <td>usl.</td>
            <td class="text-right">${formatKm(deliveryPrice)} KM</td>
            <td class="text-right"><strong>${formatKm(deliveryPrice)} KM</strong></td>
        </tr>
    ` : "";

    return `
        <section class="invoice-page">
            <div class="invoice-toolbar no-print">
                <button class="back-button" data-go-invoice-list>← Računi</button>
                <div class="invoice-toolbar-actions">
                    <span class="invoice-status-badge ${invoiceStatusClass(order)}">${invoiceStatusLabel(order)}</span>
                    <button class="secondary-button" id="invoice-print" ${!items.length || !saved ? "disabled" : ""}>🖨️ Printaj</button>
                    ${!saved && !cancelled && items.length && hasPermission("invoices.create")
                        ? '<button class="compact-primary" id="invoice-save">💾 Snimi račun</button>' : ""}
                    ${saved && hasPermission("invoices.edit")
                        ? '<button class="danger-button" id="invoice-cancel">↩ Storniraj</button>' : ""}
                </div>
            </div>

            <div class="invoice-preview-summary no-print">
                <div>
                    <span>STAVKE</span>
                    <strong>${formatKm(itemsTotal)} KM</strong>
                </div>
                <div>
                    <span>DOSTAVA</span>
                    <strong>${formatKm(deliveryPrice)} KM</strong>
                </div>
                <div>
                    <span>UKUPNO</span>
                    <strong>${formatKm(total)} KM</strong>
                </div>
            </div>

            <article class="invoice-document" id="invoice-document">
                <header class="invoice-header">
                    <div class="invoice-company">
                        <img src="/logo.jpg" alt="Super Clean logo">
                        <div>
                            <h1>SUPER CLEAN TEPIH SERVIS</h1>
                            <p>Banja Luka</p>
                            <p>Telefon: 066 311 221</p>
                            <p>E-mail: superclean.bl@gmail.com</p>
                            <p>superclean.bl</p>
                        </div>
                    </div>
                    <div class="invoice-title">
                        <span>RAČUN</span>
                        <div><b>Br. računa:</b><strong>${order.invoiceNumber ? escapeHtml(invoiceNumber(order)) : "—"}</strong></div>
                        <div><b>Br. nar.:</b><strong>${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</strong></div>
                        <div><b>Br. tepiha:</b><strong>${items.length} kom.</strong></div>
                        <div><b>Datum računa:</b><strong>${escapeHtml(formatDateBs(order.invoiceIssuedAt || order.orderDate))}</strong></div>
                        ${order.invoicePaymentMethod === "bank" && order.invoiceDueDate
                            ? `<div><b>Datum dospijeća:</b><strong>${escapeHtml(formatDateBs(order.invoiceDueDate))}</strong></div>`
                            : ""}
                    </div>
                </header>

                <div class="invoice-info-grid">
                    <section class="invoice-info-box">
                        <h2>PODACI KUPCA</h2>
                        <p><b>Ime i prezime:</b> ${escapeHtml(order.customerName || "—")}</p>
                        <p><b>Telefon:</b> ${escapeHtml(order.phone || "—")}</p>
                        <p><b>Adresa:</b> ${escapeHtml(order.address || "—")}${order.city ? `, ${escapeHtml(order.city)}` : ""}</p>
                    </section>
                    <section class="invoice-info-box">
                        <h2>NAPOMENA</h2>
                        <p>${escapeHtml(order.note || "—")}</p>
                    </section>
                </div>

                <div class="invoice-table-wrap">
                    <table class="invoice-table">
                        <thead>
                            <tr>
                                <th>R. br.</th>
                                <th>USLUGA / OPIS</th>
                                <th>DIMENZIJA / OPIS</th>
                                <th>m² / KOM</th>
                                <th>JM</th>
                                <th>CIJENA</th>
                                <th>IZNOS</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${rows || `
                                <tr>
                                    <td colspan="7" class="invoice-empty">Mjerenje još nije uneseno.</td>
                                </tr>
                            `}
                            ${deliveryRow}
                        </tbody>
                    </table>
                </div>

                <div class="invoice-total-box">
                    <div><span>UKUPNO PRIJE POPUSTA:</span><strong>${formatKm(total)} KM</strong></div>
                    <div><span>UKUPNO POPUST:</span><strong>0.00 KM</strong></div>
                    <div class="invoice-grand-total"><span>UKUPNO ZA UPLATU:</span><strong>${formatKm(total)} KM</strong></div>
                </div>

                <section class="invoice-payment">
                    <h2>NAČIN PLAĆANJA</h2>
                    <label><input type="radio" name="invoice-payment" value="cash" ${paymentMethod === "cash" ? "checked" : ""} ${saved || cancelled ? "disabled" : ""}> GOTOVINSKI</label>
                    <label><input type="radio" name="invoice-payment" value="card" ${paymentMethod === "card" ? "checked" : ""} ${saved || cancelled ? "disabled" : ""}> KARTIČNO</label>
                    <label><input type="radio" name="invoice-payment" value="bank" ${paymentMethod === "bank" ? "checked" : ""} ${saved || cancelled ? "disabled" : ""}> ŽIRALNO</label>
                    <div class="invoice-due-date" id="invoice-due-date" ${paymentMethod === "bank" ? "" : 'hidden'}>
                        <label for="invoice-due-date-input">Datum dospijeća</label>
                        <input id="invoice-due-date-input" type="date"
                            value="${escapeHtml(order.invoiceDueDate || "")}"
                            ${saved || cancelled ? "disabled" : ""}
                            min="${escapeHtml(order.invoiceIssuedAt || order.orderDate || new Date().toISOString().slice(0, 10))}">
                        <small>Obavezno samo za žiralno plaćanje.</small>
                    </div>
                    ${saved ? `<div class="invoice-payment-confirmed">Plaćanje: <strong>${paymentMethodLabel(paymentMethod)}</strong>${paymentMethod === "bank" && order.invoiceDueDate ? ` · Dospijeće: <strong>${escapeHtml(formatDateBs(order.invoiceDueDate))}</strong>` : ""}</div>` : ""}
                </section>

                <div class="invoice-signatures">
                    <div><span>Izdao račun</span></div>
                    <div><span>Primio / platio</span></div>
                </div>

                <footer class="invoice-footer">
                    Hvala što birate Super Clean tepih servis!
                </footer>
            </article>
        </section>
    `;
}

async function openInvoice(orderId) {
    try {
        const data = await api(`/api/orders/${orderId}`);
        const content = document.getElementById("page-content");
        content.innerHTML = invoiceContent(data.order, data.items);
        bindInvoicePage(data.order, data.items);
    } catch (error) {
        window.alert(error.message);
    }
}

function bindInvoicePage(order, items) {
    document.querySelector("[data-go-invoice-list]")?.addEventListener("click", () => navigate("invoices"));

    const paymentInputs = document.querySelectorAll('input[name="invoice-payment"]');
    const dueDateBox = document.getElementById("invoice-due-date");
    const dueDateInput = document.getElementById("invoice-due-date-input");

    function syncDueDateField() {
        const method = document.querySelector('input[name="invoice-payment"]:checked')?.value || "cash";
        if (dueDateBox) {
            dueDateBox.hidden = method !== "bank";
        }
        if (dueDateInput) {
            dueDateInput.required = method === "bank";
        }
    }

    paymentInputs.forEach((input) => input.addEventListener("change", syncDueDateField));
    syncDueDateField();

    document.getElementById("invoice-print")?.addEventListener("click", () => {
        if (!items.length) {
            window.alert("Prvo unesite mjerenje.");
            return;
        }
        if (order.invoiceStatus !== "INVOICED") {
            window.alert("Prvo snimi račun.");
            return;
        }
        window.print();
    });

    document.getElementById("invoice-save")?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        const paymentMethod = document.querySelector('input[name="invoice-payment"]:checked')?.value || "cash";
        const dueDate = document.getElementById("invoice-due-date-input")?.value || null;

        if (paymentMethod === "bank" && !dueDate) {
            window.alert("Za žiralno plaćanje unesite datum dospijeća.");
            return;
        }

        button.disabled = true;

        try {
            await api("/api/invoices", {
                method: "POST",
                body: JSON.stringify({
                    orderId: order.id,
                    paymentMethod,
                    dueDate: paymentMethod === "bank" ? dueDate : null,
                }),
            });
            await openInvoice(order.id);
        } catch (error) {
            button.disabled = false;
            window.alert(error.message);
        }
    });

    document.getElementById("invoice-cancel")?.addEventListener("click", async (event) => {
        if (!window.confirm(`Stornirati račun ${invoiceNumber(order)}? Račun ostaje sačuvan u evidenciji.`)) return;

        const button = event.currentTarget;
        button.disabled = true;

        try {
            await api(`/api/invoices/${order.invoiceId}/cancel`, {
                method: "PATCH",
            });
            await openInvoice(order.id);
        } catch (error) {
            button.disabled = false;
            window.alert(error.message);
        }
    });
}

function invoiceListContent(orders = [], search = "") {
    const rows = orders.map((order) => {
        const status = invoiceStatusLabel(order);
        const itemsTotal = Number(order.itemsTotal || 0);
        const deliveryPrice = Number(order.deliveryPrice || 0);
        const total = Number((itemsTotal + deliveryPrice).toFixed(2));
        const hasItems = itemsTotal > 0;
        return `
            <article class="invoice-list-card ${invoiceStatusClass(order)}">
                <div class="invoice-list-main">
                    <div class="invoice-list-topline">
                        <span class="invoice-order-code">${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</span>
                        <span class="invoice-status-badge ${invoiceStatusClass(order)}">${status}</span>
                    </div>
                    <strong>${escapeHtml(order.customerName || "Bez kupca")}</strong>
                    <span>${order.invoiceNumber ? `Račun ${escapeHtml(invoiceNumber(order))} · ` : ""}${escapeHtml(formatDateBs(order.invoiceIssuedAt || order.orderDate))}</span>
                </div>
                <div class="invoice-list-right">
                    <div class="invoice-list-amount">
                        <strong class="invoice-list-total">${formatKm(total)} KM</strong>
                        <span>${hasItems ? `${formatKm(itemsTotal)} KM stavke${deliveryPrice > 0 ? ` + ${formatKm(deliveryPrice)} KM dostava` : ""}` : "Bez mjerenja"}</span>
                    </div>
                    <button class="compact-primary open-invoice" data-order-id="${escapeHtml(order.id)}">🧾 Otvori račun</button>
                </div>
            </article>
        `;
    }).join("");

    return `
        <section class="page-panel">
            <button class="back-button" data-go-home>← Početna</button>
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">RAČUNI</span>
                    <h2>Računi</h2>
                </div>
            </div>
            <div class="module-search">
                <span>🔎</span>
                <input id="invoice-search" value="${escapeHtml(search)}"
                    placeholder="N123, broj računa, kupac, telefon..." autocomplete="off">
            </div>
            <p class="section-description">Račun se pravi iz narudžbe i mjerenja. Dostava je posebna stavka. Snimanjem račun postaje fakturisan.</p>
            <div class="invoice-list">
                ${rows || '<div class="empty-state">Nema narudžbi za prikaz računa.</div>'}
            </div>
        </section>
    `;
}

async function loadInvoices(search = "") {
    const data = await api(`/api/invoices?search=${encodeURIComponent(search)}`);
    const content = document.getElementById("page-content");
    content.innerHTML = invoiceListContent(data.invoices, search);
    bindInvoices();
}

function bindInvoices() {
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));

    const searchInput = document.getElementById("invoice-search");
    let timer;
    searchInput?.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(() => loadInvoices(searchInput.value.trim()), 250);
    });

    document.querySelectorAll(".open-invoice").forEach((button) => {
        button.addEventListener("click", () => openInvoice(button.dataset.orderId));
    });
}


function reportsContent(data, from, to) {
    const summary = data.summary || {};
    const dailyRows = (data.daily || []).map((row) => `
        <tr>
            <td>${escapeHtml(formatDateBs(String(row.report_date).slice(0, 10)))}</td>
            <td>${row.invoiced_count}</td>
            <td>${row.cancelled_count}</td>
            <td>${row.invoiced_count ? formatKm(row.invoiced_total) : "0.00"} KM</td>
            <td>${row.cancelled_count ? formatKm(row.cancelled_total) : "0.00"} KM</td>
        </tr>
    `).join("");

    return `
        <section class="page-panel">
            <button class="back-button" data-go-home>← Početna</button>
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">IZVJEŠTAJI</span>
                    <h2>Pregled poslovanja</h2>
                </div>
            </div>

            <form id="report-filter" class="report-filter">
                <label>Od
                    <input type="date" name="from" value="${escapeHtml(from)}" required>
                </label>
                <label>Do
                    <input type="date" name="to" value="${escapeHtml(to)}" required>
                </label>
                <button class="compact-primary" type="submit">🔎 Prikaži</button>
                ${hasPermission("reports.export") ? '<button class="secondary-button" type="button" id="report-export">📤 Izvoz</button>' : ""}
            </form>

            <div class="report-cards">
                <article class="report-card"><span>Fakturisano</span><strong>${formatKm(summary.invoiced_total)} KM</strong><small>${summary.invoiced_count || 0} računa</small></article>
                <article class="report-card"><span>Stornirano</span><strong>${formatKm(summary.cancelled_total)} KM</strong><small>${summary.cancelled_count || 0} računa</small></article>
                <article class="report-card"><span>Broj tepiha</span><strong>${summary.carpet_count || 0}</strong><small>fakturisani računi</small></article>
                <article class="report-card"><span>Dostava</span><strong>${formatKm(summary.delivery_total)} KM</strong><small>u fakturisanim računima</small></article>
            </div>

            <section class="report-table-wrap">
                <h3>Dnevni pregled</h3>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Datum</th>
                            <th>Fakturisano</th>
                            <th>Stornirano</th>
                            <th>Iznos fakturisano</th>
                            <th>Iznos stornirano</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${dailyRows || '<tr><td colspan="5" class="empty-cell">Nema računa u izabranom periodu.</td></tr>'}
                    </tbody>
                </table>
            </section>
        </section>
    `;
}

function defaultReportDates() {
    const now = new Date();
    const first = new Date(now.getFullYear(), now.getMonth(), 1);
    const format = (date) => {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, "0");
        const day = String(date.getDate()).padStart(2, "0");
        return `${year}-${month}-${day}`;
    };
    return { from: format(first), to: format(now) };
}

async function loadReports(from = "", to = "") {
    const dates = from && to ? { from, to } : defaultReportDates();
    const data = await api(`/api/reports/summary?from=${encodeURIComponent(dates.from)}&to=${encodeURIComponent(dates.to)}`);
    const content = document.getElementById("page-content");
    content.innerHTML = reportsContent(data, dates.from, dates.to);
    bindReports();
}

function bindReports() {
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));

    document.getElementById("report-filter")?.addEventListener("submit", async (event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        try {
            await loadReports(String(form.get("from")), String(form.get("to")));
        } catch (error) {
            window.alert(error.message);
        }
    });

    document.getElementById("report-export")?.addEventListener("click", async () => {
        const form = document.getElementById("report-filter");
        const values = new FormData(form);
        try {
            const data = await api(`/api/reports/summary?from=${encodeURIComponent(values.get("from"))}&to=${encodeURIComponent(values.get("to"))}`);
            const rows = [
                ["Datum", "Fakturisano računa", "Stornirano računa", "Fakturisano KM", "Stornirano KM"],
                ...(data.daily || []).map((row) => [
                    String(row.report_date).slice(0, 10),
                    row.invoiced_count,
                    row.cancelled_count,
                    Number(row.invoiced_total || 0).toFixed(2),
                    Number(row.cancelled_total || 0).toFixed(2),
                ]),
            ];
            const csv = rows.map((row) => row.map((value) => `"${String(value).replaceAll('"', '""')}"`).join(";")).join("\n");
            const blob = new Blob(["\ufeff" + csv], { type: "text/csv;charset=utf-8" });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.download = `super-clean-izvjestaj-${values.get("from")}-${values.get("to")}.csv`;
            link.click();
            URL.revokeObjectURL(url);
        } catch (error) {
            window.alert(error.message);
        }
    });
}

function labelsContent(orders = []) {
    return `
        <section class="page-panel">
            <button class="back-button" data-go-home>← Početna</button>
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">ETIKETE</span>
                    <h2>Etikete za tepihe</h2>
                </div>
            </div>
            <p class="section-description">Izaberi narudžbu i odštampaj etikete. Svaka izmjerena stavka dobija svoju etiketu sa brojem narudžbe i QR kodom.</p>
            <div class="labels-list">
                ${orders.map((order) => `
                    <article class="label-order-card">
                        <div>
                            <span class="eyebrow">NARUDŽBA ${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</span>
                            <strong>${escapeHtml(order.customerName || "Bez kupca")}</strong>
                            <span>${escapeHtml(formatDateBs(order.orderDate))}${order.address ? ` · ${escapeHtml(order.address)}` : ""}</span>
                        </div>
                        <button class="compact-primary open-labels" data-order-id="${escapeHtml(order.id)}">🏷️ Etikete</button>
                    </article>
                `).join("") || '<div class="empty-state">Nema narudžbi.</div>'}
            </div>
        </section>
    `;
}

async function loadLabelsPage() {
    const data = await api("/api/orders?search=");
    const content = document.getElementById("page-content");
    content.innerHTML = labelsContent(data.orders);
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
    document.querySelectorAll(".open-labels").forEach((button) => {
        button.addEventListener("click", () => openLabels(button.dataset.orderId));
    });
}

function labelDocument(order, item, carpetNumber, carpetCount) {
    const qrUrl = `/api/qr/order/${encodeURIComponent(order.id)}/item/${encodeURIComponent(item.id)}`;
    const dimension = item.unit === "m2"
        ? `${item.lengthM} × ${item.widthM} m`
        : `${item.quantity} kom.`;
    const orderCode = `N${order.orderNumber}`;
    return `
        <article class="carpet-label">
            <div class="label-brand">
                <div class="label-logo-block">
                    <img src="/logo.jpg" alt="Super Clean">
                    <b>066 311 221</b>
                </div>
                <div class="label-brand-copy">
                    <strong>SUPER CLEAN</strong>
                    <span>TEPIH SERVIS · BANJA LUKA</span>
                </div>
            </div>

            <div class="label-identifiers">
                <div class="label-order-code">
                    <span>BR. NARUDŽBE</span>
                    <strong>${escapeHtml(orderCode)}</strong>
                </div>
                <div class="label-carpet-code">
                    <span>TEPIH</span>
                    <strong>${carpetNumber}/${carpetCount}</strong>
                </div>
            </div>

            <div class="label-body">
                <div class="label-details">
                    <div class="label-customer">
                        <span>KUPAC</span>
                        <strong>${escapeHtml(order.customerName || "Bez kupca")}</strong>
                    </div>
                    ${order.phone ? `<span class="label-customer-phone">📞 ${escapeHtml(order.phone)}</span>` : ""}
                    ${order.address ? `<span>📍 ${escapeHtml(order.address)}${order.city ? ` · ${escapeHtml(order.city)}` : ""}</span>` : ""}
                    <hr>
                    <span><b>Usluga:</b> ${escapeHtml(item.serviceName)}</span>
                    <span><b>Dimenzija:</b> ${escapeHtml(dimension)}</span>
                    ${item.areaM2 !== null ? `<span><b>Površina:</b> ${escapeHtml(item.areaM2.toFixed(2))} m²</span>` : ""}
                    ${item.note ? `<span><b>Napomena:</b> ${escapeHtml(item.note)}</span>` : ""}
                </div>
                <div class="label-qr">
                    <img src="${qrUrl}" alt="QR kod za ${escapeHtml(orderCode)} - tepih ${carpetNumber}">
                    <span>QR · ${escapeHtml(orderCode)} · ${carpetNumber}/${carpetCount}</span>
                </div>
            </div>
            <div class="label-footer">ČISTO • BRZO • PROFESIONALNO</div>
        </article>
    `;
}

function labelsDocument(order, items) {
    const canPrint = hasPermission("labels.print");
    return `
        <section class="page-panel labels-page">
            <div class="invoice-toolbar no-print">
                <button class="back-button" data-go-labels>← Etikete</button>
                <div class="invoice-toolbar-actions">
                    ${canPrint ? '<button class="compact-primary" id="labels-print">🖨️ Print</button>' : ""}
                </div>
            </div>
            <div class="labels-print-area">
                ${items.map((item, index) => labelDocument(order, item, index + 1, items.length)).join("") || '<div class="empty-state">Ova narudžba još nema izmjerenih stavki.</div>'}
            </div>
        </section>
    `;
}

async function openLabels(orderId) {
    try {
        const data = await api(`/api/orders/${orderId}`);
        const content = document.getElementById("page-content");
        content.innerHTML = labelsDocument(data.order, data.items);
        document.querySelector("[data-go-labels]")?.addEventListener("click", () => navigate("labels"));
        document.getElementById("labels-print")?.addEventListener("click", () => window.print());
    } catch (error) {
        window.alert(error.message);
    }
}

function placeholderContent(title) {
    return `
        <section class="page-panel">
            <button class="back-button" data-go-home>← Početna</button>
            <h2>${escapeHtml(title)}</h2>
            <p>Modul je spreman za povezivanje sa poslovnim podacima.</p>
        </section>
    `;
}

function customersContent(customers = [], search = "") {
    const canCreate = hasPermission("customers.create");
    const canEdit = hasPermission("customers.edit");
    const canDelete = hasPermission("customers.delete");

    const rows = customers.map((customer) => {
        const fullName = `${customer.firstName} ${customer.lastName}`.trim();
        const displayName = customer.companyName || fullName;
        const initials = `${customer.firstName.charAt(0)}${customer.lastName.charAt(0)}`.toUpperCase();

        return `
            <article class="customer-card" data-customer-id="${escapeHtml(customer.id)}">
                <div class="user-avatar">${escapeHtml(initials || "K")}</div>
                <div class="customer-info">
                    <strong>${escapeHtml(displayName)}</strong>
                    ${customer.companyName ? `<span>${escapeHtml(fullName)}</span>` : ""}
                    <span>${escapeHtml(customer.phone || "Bez telefona")}</span>
                    <span>${escapeHtml(customer.city || "")}${customer.address ? ` · ${escapeHtml(customer.address)}` : ""}</span>
                    ${customer.latitude !== null && customer.longitude !== null
                        ? '<span class="location-saved">📍 Lokacija sačuvana</span>' : ""}
                </div>
                <div class="customer-actions">
                    <button class="customer-history" data-customer-id="${escapeHtml(customer.id)}" aria-label="Istorija kupca">📋</button>
                    ${customer.latitude !== null && customer.longitude !== null
                        ? `<button class="navigate-customer" data-latitude="${escapeHtml(customer.latitude)}" data-longitude="${escapeHtml(customer.longitude)}" data-address="${escapeHtml(customer.address || "")}" data-city="${escapeHtml(customer.city || "")}" aria-label="Navigacija do kupca">🚗</button>`
                        : ""}
                    ${canEdit ? `<button class="edit-customer" data-customer-id="${escapeHtml(customer.id)}" aria-label="Izmijeni kupca">✏️</button>` : ""}
                    ${canDelete ? `<button class="delete-customer" data-customer-id="${escapeHtml(customer.id)}" aria-label="Obriši kupca">🗑️</button>` : ""}
                </div>
            </article>
        `;
    }).join("");

    return `
        <section class="page-panel">
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">BAZA KUPACA</span>
                    <h2>Kupci</h2>
                </div>
                ${canCreate ? `<button class="compact-primary" id="add-customer">➕ Dodaj</button>` : ""}
            </div>

            <div class="module-search">
                <span>🔎</span>
                <input id="customer-search" value="${escapeHtml(search)}"
                    placeholder="Ime, telefon, adresa..." autocomplete="off">
            </div>

            <div id="customer-list" class="customer-list">
                ${rows || '<div class="empty-state">Nema pronađenih kupaca.</div>'}
            </div>
        </section>
    `;
}


function formatCustomerHistoryStatus(status) {
    if (status === "INVOICED") return '<span class="history-status history-status-invoiced">🔵 FAKTURISANO</span>';
    if (status === "CANCELLED") return '<span class="history-status history-status-cancelled">🔴 STORNIRANO</span>';
    return '<span class="history-status history-status-preparing">⚪ U PRIPREMI</span>';
}

function customerHistoryContent(data) {
    const customer = data.customer;
    const totals = data.totals;
    const displayName = customer.companyName ||
        `${customer.firstName || ""} ${customer.lastName || ""}`.trim() ||
        "Kupac";

    const orders = data.orders.map((order) => `
        <article class="history-order">
            <div class="history-order-row">
                <button class="history-order-main" data-history-order-id="${escapeHtml(order.id)}">
                    <div>
                        <strong>${escapeHtml(order.orderCode)}</strong>
                        <span>${escapeHtml(formatDateBs(order.orderDate))} · ${order.itemCount} ${order.itemCount === 1 ? "tepih" : "tepiha"}</span>
                    </div>
                    <div class="history-order-total">
                        <strong>${formatKm(order.total)}</strong>
                        ${formatCustomerHistoryStatus(order.invoiceStatus)}
                    </div>
                </button>
                ${hasPermission("orders.create")
                    ? `<button class="history-repeat-order" data-repeat-order-id="${escapeHtml(order.id)}" type="button">↻ Ponovi</button>`
                    : ""}
            </div>
            ${order.invoiceNumber
                ? `<div class="history-order-meta">🧾 Račun ${escapeHtml(formatInvoiceNumber(order.invoiceNumber, order.invoiceIssuedAt))}</div>`
                : `<div class="history-order-meta">🧾 Račun nije kreiran</div>`}
        </article>
    `).join("");

    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card customer-history-modal" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <div class="history-header">
                    <div class="user-avatar">${escapeHtml(
                        `${customer.firstName || ""}${customer.lastName || ""}`.slice(0, 2).toUpperCase() || "K"
                    )}</div>
                    <div>
                        <span class="eyebrow">ISTORIJA KUPCA</span>
                        <h2>${escapeHtml(displayName)}</h2>
                        ${customer.companyName
                            ? `<span>${escapeHtml(`${customer.firstName || ""} ${customer.lastName || ""}`.trim())}</span>`
                            : ""}
                    </div>
                </div>

                <div class="history-contact">
                    ${customer.phone ? `<span>📞 ${escapeHtml(customer.phone)}</span>` : ""}
                    ${customer.address || customer.city
                        ? `<span>📍 ${escapeHtml([customer.address, customer.city].filter(Boolean).join(" · "))}</span>`
                        : ""}
                </div>

                <div class="customer-history-stats">
                    <div><strong>${totals.orderCount}</strong><span>Narudžbi</span></div>
                    <div><strong>${totals.carpetCount}</strong><span>Tepisa</span></div>
                    <div><strong>${formatKm(totals.totalSpent)}</strong><span>Potrošeno</span></div>
                </div>

                <div class="history-section-heading">
                    <h3>Sve narudžbe</h3>
                    <span>${data.orders.length}</span>
                </div>

                <div class="history-orders">
                    ${orders || '<div class="empty-state">Kupac još nema narudžbi.</div>'}
                </div>
            </section>
        </div>
    `;
}

async function openCustomerHistory(customerId) {
    try {
        const data = await api(`/api/customers/${customerId}/history`);
        openModal(customerHistoryContent(data));

        document.querySelectorAll(".history-order-main").forEach((button) => {
            button.addEventListener("click", async () => {
                const orderId = button.dataset.historyOrderId;
                document.getElementById("modal-root").innerHTML = "";
                await openOrderDetail(orderId);
            });
        });

        document.querySelectorAll(".history-repeat-order").forEach((button) => {
            button.addEventListener("click", async () => {
                const orderId = button.dataset.repeatOrderId;
                const confirmed = window.confirm(
                    "Ponoviti ovu narudžbu? Kupac, mjere, stavke, cijene i dostava biće kopirani. Račun se ne kopira."
                );
                if (!confirmed) return;

                try {
                    const data = await api(`/api/orders/${orderId}/repeat`, {
                        method: "POST",
                    });
                    document.getElementById("modal-root").innerHTML = "";
                    await openOrderDetail(data.order.id);
                } catch (error) {
                    window.alert(error.message);
                }
            });
        });
    } catch (error) {
        window.alert(error.message);
    }
}

function openNavigation(latitude, longitude, address = "", city = "") {
    if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
        window.alert("Kupac nema sačuvanu GPS lokaciju.");
        return;
    }

    const destination = `${latitude},${longitude}`;
    const url = new URL("https://www.google.com/maps/dir/");
    url.searchParams.set("api", "1");
    url.searchParams.set("destination", destination);

    void address;
    void city;

    window.open(url.toString(), "_blank", "noopener,noreferrer");
}

function customerForm(customer = null, returnToOrder = false) {
    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card customer-modal" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <h2>${customer ? "Izmijeni kupca" : "Novi kupac"}</h2>
                <form id="customer-form" ${customer ? `data-customer-id="${escapeHtml(customer.id)}"` : ""} data-return-to-order="${returnToOrder ? "true" : "false"}">
                    <label>Ime
                        <input name="firstName" value="${escapeHtml(customer?.firstName || "")}" required maxlength="100" autocomplete="given-name">
                    </label>
                    <label>Prezime
                        <input name="lastName" value="${escapeHtml(customer?.lastName || "")}" maxlength="100" autocomplete="family-name">
                    </label>
                    <label>Naziv firme
                        <input name="companyName" value="${escapeHtml(customer?.companyName || "")}" maxlength="200">
                    </label>
                    <label>Telefon
                        <input name="phone" value="${escapeHtml(customer?.phone || "")}" maxlength="40" inputmode="tel" autocomplete="tel">
                    </label>
                    <label>WhatsApp
                        <input name="whatsapp" value="${escapeHtml(customer?.whatsapp || "")}" maxlength="40" inputmode="tel">
                    </label>

                    <label>Adresa / zgrada / lamela
                        <input id="customer-address" name="address" value="${escapeHtml(customer?.address || "")}"
                            maxlength="250" autocomplete="street-address"
                            placeholder="npr. Bulevar vojvode Stepe 25">
                    </label>
                    <label>Grad
                        <input id="customer-city" name="city" value="${escapeHtml(customer?.city || "Banja Luka")}"
                            maxlength="100" autocomplete="address-level2">
                    </label>

                    <div class="map-actions">
                        <button type="button" class="secondary-button" id="find-customer-address">🔎 Pronađi adresu</button>
                        <button type="button" class="secondary-button" id="use-my-location">📍 Moja lokacija</button>
                    </div>
                    <div id="geocode-message" class="map-message" aria-live="polite"></div>
                    <div id="geocode-results" class="geocode-results hidden"></div>
                    <div id="customer-map" class="customer-map" aria-label="Mapa lokacije kupca"></div>
                    <input type="hidden" name="latitude" value="${customer?.latitude ?? ""}">
                    <input type="hidden" name="longitude" value="${customer?.longitude ?? ""}">

                    <label>Napomena
                        <textarea name="note" maxlength="5000" rows="4">${escapeHtml(customer?.note || "")}</textarea>
                    </label>
                    <label class="switch-row">Aktivan
                        <input name="isActive" type="checkbox" ${customer?.isActive !== false ? "checked" : ""}>
                    </label>
                    <button class="primary-button">${customer ? "Sačuvaj izmjene" : "Dodaj kupca"}</button>
                </form>
            </section>
        </div>
    `;
}

async function loadCustomers(search = "") {
    const data = await api(`/api/customers?search=${encodeURIComponent(search)}`);
    const content = document.getElementById("page-content");
    content.innerHTML = customersContent(data.customers, search);
    bindCustomers();
}

function bindCustomers() {
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
    document.getElementById("add-customer")?.addEventListener("click", () => openModal(customerForm()));

    const searchInput = document.getElementById("customer-search");
    let timer;
    searchInput?.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(() => loadCustomers(searchInput.value.trim()), 250);
    });

    document.querySelectorAll(".customer-history").forEach((button) => {
        button.addEventListener("click", () => openCustomerHistory(button.dataset.customerId));
    });

    document.querySelectorAll(".edit-customer").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                const data = await api(`/api/customers/${button.dataset.customerId}`);
                openModal(customerForm(data.customer));
            } catch (error) {
                window.alert(error.message);
            }
        });
    });

    document.querySelectorAll(".navigate-customer").forEach((button) => {
        button.addEventListener("click", () => {
            openNavigation(
                Number(button.dataset.latitude),
                Number(button.dataset.longitude),
                button.dataset.address || "",
                button.dataset.city || "",
            );
        });
    });

    document.querySelectorAll(".delete-customer").forEach((button) => {
        button.addEventListener("click", async () => {
            if (!window.confirm("Obrisati ovog kupca?")) return;
            try {
                await api(`/api/customers/${button.dataset.customerId}`, { method: "DELETE" });
                await loadCustomers(searchInput?.value.trim() || "");
            } catch (error) {
                window.alert(error.message);
            }
        });
    });
}

let customerMap = null;
let customerMarker = null;

function setCustomerCoordinates(latitude, longitude, message = "") {
    const form = document.getElementById("customer-form");
    if (!form) return;

    form.latitude.value = String(latitude);
    form.longitude.value = String(longitude);

    if (customerMap && customerMarker) {
        const position = [latitude, longitude];
        customerMarker.setLatLng(position);
        customerMap.setView(position, 16);
    }

    const messageElement = document.getElementById("geocode-message");
    if (messageElement) messageElement.textContent = message;
}

function initializeCustomerMap() {
    if (!window.L) {
        const message = document.getElementById("geocode-message");
        if (message) message.textContent = "Mapa se trenutno ne može učitati.";
        return;
    }

    const form = document.getElementById("customer-form");
    const mapElement = document.getElementById("customer-map");
    if (!form || !mapElement) return;

    const latitude = Number(form.latitude.value);
    const longitude = Number(form.longitude.value);
    const hasCoordinates = Number.isFinite(latitude) && Number.isFinite(longitude);
    const defaultPosition = [44.7722, 17.1910];
    const position = hasCoordinates ? [latitude, longitude] : defaultPosition;

    customerMap = L.map(mapElement, { scrollWheelZoom: false }).setView(position, hasCoordinates ? 16 : 12);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap',
    }).addTo(customerMap);

    customerMarker = L.marker(position, { draggable: true }).addTo(customerMap);
    customerMarker.bindPopup(hasCoordinates ? "Sačuvana lokacija kupca" : "Pomjeri pin na tačnu lokaciju").openPopup();

    customerMarker.on("dragend", () => {
        const point = customerMarker.getLatLng();
        setCustomerCoordinates(point.lat, point.lng, "Lokacija je ručno postavljena.");
    });

    document.getElementById("find-customer-address")?.addEventListener("click", findCustomerAddress);
    document.getElementById("use-my-location")?.addEventListener("click", useMyLocation);

    window.setTimeout(() => customerMap.invalidateSize(), 100);
}

async function findCustomerAddress() {
    const address = document.getElementById("customer-address")?.value.trim();
    const city = document.getElementById("customer-city")?.value.trim();
    const message = document.getElementById("geocode-message");
    const resultsElement = document.getElementById("geocode-results");

    if (!address || address.length < 3) {
        if (message) message.textContent = "Prvo upiši adresu.";
        return;
    }

    if (message) message.textContent = "Tražim adresu...";
    if (resultsElement) {
        resultsElement.innerHTML = "";
        resultsElement.classList.add("hidden");
    }

    try {
        const data = await api(`/api/geocode?address=${encodeURIComponent(address)}&city=${encodeURIComponent(city || "Banja Luka")}`);

        if (!data.results.length) {
            if (message) message.textContent = "Adresa nije pronađena. Probaj dodati broj zgrade ili naselje.";
            return;
        }

        if (data.results.length === 1) {
            applyGeocodeResult(data.results[0]);
            return;
        }

        if (resultsElement) {
            resultsElement.innerHTML = `
                <span class="map-message">Pronađeno je više mogućih lokacija:</span>
                ${data.results.map((result, index) => `
                    <button type="button" class="geocode-result" data-result-index="${index}">
                        ${escapeHtml(result.displayName)}
                    </button>
                `).join("")}
            `;
            resultsElement.classList.remove("hidden");
            resultsElement.querySelectorAll(".geocode-result").forEach((button, index) => {
                button.addEventListener("click", () => applyGeocodeResult(data.results[index]));
            });
        }
        if (message) message.textContent = "Izaberi tačnu lokaciju.";
    } catch (error) {
        if (message) message.textContent = error.message;
    }
}

function applyGeocodeResult(result) {
    setCustomerCoordinates(result.latitude, result.longitude, "Lokacija pronađena. Provjeri pin na mapi prije čuvanja.");
    const resultsElement = document.getElementById("geocode-results");
    if (resultsElement) resultsElement.classList.add("hidden");
}

function useMyLocation() {
    const message = document.getElementById("geocode-message");
    if (!navigator.geolocation) {
        if (message) message.textContent = "Ovaj telefon ne podržava GPS lokaciju.";
        return;
    }

    if (message) message.textContent = "Čekam GPS lokaciju...";
    navigator.geolocation.getCurrentPosition(
        (position) => {
            setCustomerCoordinates(
                position.coords.latitude,
                position.coords.longitude,
                "Preuzeta je trenutna lokacija telefona. Pomjeri pin ako treba."
            );
        },
        (error) => {
            const messageByCode = {
                1: "Dozvola za lokaciju nije odobrena.",
                2: "Lokacija trenutno nije dostupna.",
                3: "Traženje lokacije je isteklo.",
            };
            if (message) message.textContent = messageByCode[error.code] || "Nije moguće očitati lokaciju.";
        },
        { enableHighAccuracy: true, timeout: 10000, maximumAge: 30000 },
    );
}

async function handleCustomerSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const id = form.dataset.customerId;
    const payload = {
        firstName: form.firstName.value.trim(),
        lastName: form.lastName.value.trim(),
        companyName: form.companyName.value.trim(),
        phone: form.phone.value.trim(),
        whatsapp: form.whatsapp.value.trim(),
        address: form.address.value.trim(),
        city: form.city.value.trim(),
        note: form.note.value.trim(),
        latitude: form.latitude.value ? Number(form.latitude.value) : null,
        longitude: form.longitude.value ? Number(form.longitude.value) : null,
        isActive: form.isActive.checked,
    };

    try {
        const data = await api(id ? `/api/customers/${id}` : "/api/customers", {
            method: id ? "PUT" : "POST",
            body: JSON.stringify(payload),
        });

        if (!id && form.dataset.returnToOrder === "true") {
            const customers = await loadCustomersForOrder();
            const createdCustomerId = data.customer?.id;
            document.getElementById("modal-root").innerHTML = "";
            openModal(orderForm(customers, null, createdCustomerId || ""));
            bindOrderCustomerPreview();
            return;
        }

        document.getElementById("modal-root").innerHTML = "";
        await loadCustomers(document.getElementById("customer-search")?.value.trim() || "");
    } catch (error) {
        window.alert(error.message);
    }
}

function adminContent() {
    return `
        <section class="page-panel">
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">ADMINISTRATORSKI CENTAR</span>
                    <h2>Korisnici i dozvole</h2>
                </div>
            </div>
            <div class="admin-tabs">
                <button class="active" data-admin-tab="users">👥 Korisnici</button>
                <button data-admin-tab="roles">🔐 Uloge i dozvole</button>
                <button data-admin-tab="system">🛡️ Sistem</button>
            </div>
            <div id="admin-panel"></div>
        </section>
    `;
}

function renderUsers(users) {
    const rows = users.map((user) => `
        <article class="user-card">
            <div class="user-avatar">${escapeHtml(user.firstName.charAt(0) + user.lastName.charAt(0))}</div>
            <div class="user-info">
                <strong>${escapeHtml(user.firstName)} ${escapeHtml(user.lastName)}</strong>
                <span>@${escapeHtml(user.username)}</span>
                <span class="status ${user.isActive ? "active" : "inactive"}">
                    ${user.isActive ? "Aktivan" : "Neaktivan"} · ${escapeHtml(user.roleName)}
                </span>
            </div>
            <button class="edit-user" data-user-id="${user.id}" aria-label="Izmijeni korisnika">✏️</button>
        </article>
    `).join("");

    return `
        <button class="admin-add-button" id="add-user">➕ Dodaj korisnika</button>
        <div class="user-list">${rows || '<div class="empty-state">Nema korisnika.</div>'}</div>
    `;
}

function renderRoles() {
    const roleCards = rolesData.map((role) => `
        <article class="role-card">
            <div class="role-card-heading">
                <div><strong>${escapeHtml(role.name)}</strong><small>${escapeHtml(role.description || "Bez opisa")}</small></div>
                <button class="edit-role" data-role-code="${escapeHtml(role.code)}">✏️</button>
            </div>
            <div class="permission-summary">${role.permissions.length} dozvola</div>
        </article>
    `).join("");

    return `
        <button class="admin-add-button" id="add-role">➕ Dodaj ulogu</button>
        <div class="role-list">${roleCards}</div>
    `;
}

function userForm(user = null) {
    const roles = rolesData.map((role) =>
        `<option value="${escapeHtml(role.code)}" ${user?.role === role.code ? "selected" : ""}>${escapeHtml(role.name)}</option>`
    ).join("");

    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <h2>${user ? "Izmijeni korisnika" : "Novi korisnik"}</h2>
                <form id="user-form" ${user ? `data-user-id="${user.id}"` : ""}>
                    <label>Ime<input name="firstName" value="${escapeHtml(user?.firstName || "")}" required></label>
                    <label>Prezime<input name="lastName" value="${escapeHtml(user?.lastName || "")}" required></label>
                    <label>Korisničko ime<input name="username" value="${escapeHtml(user?.username || "")}" required></label>
                    <label>Uloga<select name="role" required>${roles}</select></label>
                    <label>${user ? "Nova lozinka (ostavi prazno ako se ne mijenja)" : "Lozinka"}
                        <input name="password" type="password" ${user ? "" : "required"} minlength="8">
                    </label>
                    <label class="switch-row">Aktivan
                        <input name="isActive" type="checkbox" ${user?.isActive !== false ? "checked" : ""}>
                    </label>
                    <button class="primary-button">${user ? "Sačuvaj izmjene" : "Dodaj korisnika"}</button>
                    ${user ? `<button type="button" class="danger-button" id="delete-user" data-user-id="${user.id}">Obriši korisnika</button>` : ""}
                </form>
            </section>
        </div>
    `;
}

function roleForm(role = null) {
    const selected = new Set(role?.permissions || []);
    const groups = permissionGroups.map(([module, permissions]) => `
        <fieldset>
            <legend>${escapeHtml(module)}</legend>
            ${permissions.map(([code, name]) => `
                <label class="permission-row">
                    <span>${escapeHtml(name)}</span>
                    <input type="checkbox" name="permission" value="${escapeHtml(code)}" ${selected.has(code) ? "checked" : ""}>
                </label>
            `).join("")}
        </fieldset>
    `).join("");

    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card modal-large" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <h2>${role ? "Izmijeni ulogu" : "Nova uloga"}</h2>
                <form id="role-form" ${role ? `data-role-code="${escapeHtml(role.code)}"` : ""}>
                    <label>Naziv uloge<input name="name" value="${escapeHtml(role?.name || "")}" required></label>
                    <label>Opis<input name="description" value="${escapeHtml(role?.description || "")}"></label>
                    <div class="permission-groups">${groups}</div>
                    <button class="primary-button">Sačuvaj dozvole</button>
                    ${role && !role.is_system ? `<button type="button" class="danger-button" id="delete-role" data-role-code="${escapeHtml(role.code)}">Obriši ulogu</button>` : ""}
                </form>
            </section>
        </div>
    `;
}

async function api(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    });
    const text = await response.text();
    const data = text ? JSON.parse(text) : {};
    if (!response.ok) throw new Error(data.error || "Operacija nije uspjela.");
    return data;
}

async function loadAdminData() {
    const [usersData, roles] = await Promise.all([
        api("/api/admin/users"),
        api("/api/admin/roles"),
    ]);
    rolesData = roles.roles;
    permissionsData = roles.permissions;
    return usersData.users;
}

async function showAdminTab(tab) {
    const panel = document.getElementById("admin-panel");
    if (!panel) return;

    document.querySelectorAll(".admin-tabs button").forEach((button) => {
        button.classList.toggle("active", button.dataset.adminTab === tab);
    });

    try {
        if (!rolesData.length) await loadAdminData();
        if (tab === "users") {
            const data = await api("/api/admin/users");
            panel.innerHTML = renderUsers(data.users);
            bindUserActions();
        } else if (tab === "roles") {
            panel.innerHTML = renderRoles();
            bindRoleActions();
        } else {
            panel.innerHTML = adminSystemLoadingContent();
            await loadAdminSystem();
        }
    } catch (error) {
        panel.innerHTML = `<div class="error">${escapeHtml(error.message)}</div>`;
    }
}



function adminSystemLoadingContent() {
    return `
        <div class="system-loading">
            <div class="dashboard-loading">Učitavam sigurnost sistema...</div>
        </div>
    `;
}

function formatFileSize(bytes) {
    const value = Number(bytes || 0);
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDateTimeBs(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat("bs-BA", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
    }).format(date);
}

function adminSystemContent(data, logs) {
    const lastBackup = data.lastBackup;
    const backupHealthy = data.backupAgeHours !== null && data.backupAgeHours < 36;
    const issues = data.issues || [];

    const issueHtml = issues.length
        ? issues.map((issue) => `
            <button class="system-issue" data-system-issue="${escapeHtml(issue.code)}">
                <span>⚠️</span>
                <span><strong>${escapeHtml(issue.label)}</strong><small>${issue.count}</small></span>
                <b>›</b>
            </button>
        `).join("")
        : `
            <div class="system-ok">
                <span>✅</span>
                <div><strong>Sistem je uredan</strong><small>Nema pronađenih otvorenih problema.</small></div>
            </div>
        `;

    const backupRows = (data.backups || []).map((backup) => `
        <article class="backup-row">
            <div>
                <strong>${backup.type === "AUTOMATIC" ? "🔄 Automatski" : "💾 Ručni"}</strong>
                <small>${escapeHtml(formatDateTimeBs(backup.createdAt))} · ${escapeHtml(formatFileSize(backup.sizeBytes))}</small>
            </div>
            <button class="secondary-button download-backup" data-filename="${escapeHtml(backup.filename)}">Preuzmi</button>
        </article>
    `).join("");

    const auditActionNames = {
        QR_SCAN: "QR skeniranje",
    };
    const logRows = (logs || []).map((log) => `
        <article class="audit-row">
            <div class="audit-row-top">
                <strong>${escapeHtml(auditActionNames[log.action] || log.action)}</strong>
                <span class="${Number(log.statusCode) >= 400 ? "audit-failed" : "audit-success"}">${escapeHtml(String(log.statusCode || ""))}</span>
            </div>
            <small>${escapeHtml(log.username || "sistem")} · ${escapeHtml(log.role || "")} · ${escapeHtml(formatDateTimeBs(log.createdAt))}</small>
            <small>${escapeHtml(log.method)} ${escapeHtml(log.path)}</small>
        </article>
    `).join("");

    return `
        <section class="system-grid">
            <article class="system-card backup-card">
                <div class="system-card-heading">
                    <div><span class="system-icon">💾</span><div><strong>Backup</strong><small>Poslovni podaci i podešavanja</small></div></div>
                    <span class="system-status ${backupHealthy ? "healthy" : "warning"}">${backupHealthy ? "Uredno" : "Provjeri"}</span>
                </div>
                <div class="backup-last">
                    <span>Zadnji backup</span>
                    <strong>${lastBackup ? escapeHtml(formatDateTimeBs(lastBackup.created_at)) : "Nije napravljen"}</strong>
                    <small>${lastBackup ? `${lastBackup.backup_type === "AUTOMATIC" ? "Automatski" : "Ručni"} · ${formatFileSize(lastBackup.file_size_bytes)}` : "Sistem će pokušati napraviti automatski backup."}</small>
                </div>
                <div class="system-actions system-actions-wrap">
                    <button class="compact-primary" id="create-backup">💾 Napravi backup sada</button>
                    <button class="secondary-button" id="system-self-test">🧪 Pokreni test sistema</button>
                    <label class="secondary-button backup-restore-label" for="backup-restore-input">♻️ Vrati backup</label>
                    <input id="backup-restore-input" type="file" accept=".json,application/json" hidden>
                </div>
                <div class="backup-list">${backupRows || '<div class="empty-state">Još nema backup zapisa.</div>'}</div>
            </article>

            <article class="system-card">
                <div class="system-card-heading">
                    <div><span class="system-icon">🛡️</span><div><strong>Kontrola podataka</strong><small>Provjera stvari koje mogu tražiti pažnju</small></div></div>
                </div>
                <div class="system-issues">${issueHtml}</div>
                <div class="system-counts">
                    <span>Kupci <b>${data.counts.customers}</b></span>
                    <span>Narudžbe <b>${data.counts.orders}</b></span>
                    <span>Tepisi <b>${data.counts.items}</b></span>
                    <span>Računi <b>${data.counts.invoices}</b></span>
                </div>
            </article>

            <article class="system-card audit-card">
                <div class="system-card-heading">
                    <div><span class="system-icon">📝</span><div><strong>Dnevnik aktivnosti</strong><small>Posljednjih ${logs.length} aktivnosti</small></div></div>
                    <button class="secondary-button" id="refresh-audit">Osvježi</button>
                </div>
                <div class="audit-list">${logRows || '<div class="empty-state">Nema aktivnosti.</div>'}</div>
            </article>
        </section>
    `;
}

async function loadAdminSystem() {
    const panel = document.getElementById("admin-panel");
    if (!panel) return;

    try {
        const [system, audit] = await Promise.all([
            api("/api/admin/system/status"),
            api("/api/admin/audit?limit=40"),
        ]);
        panel.innerHTML = adminSystemContent(system, audit.logs);
        bindAdminSystemActions();
    } catch (error) {
        panel.innerHTML = `<div class="error">${escapeHtml(error.message)}</div>`;
    }
}

function bindAdminSystemActions() {
    document.getElementById("create-backup")?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        button.disabled = true;
        try {
            const result = await api("/api/admin/backup", { method: "POST" });
            await downloadBackupFile(result.filename);
            await loadAdminSystem();
            window.alert("Backup je napravljen i preuzet.");
        } catch (error) {
            window.alert(error.message);
        } finally {
            button.disabled = false;
        }
    });

    document.querySelectorAll(".download-backup").forEach((button) => {
        button.addEventListener("click", () => downloadBackupFile(button.dataset.filename));
    });

    document.getElementById("system-self-test")?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        button.disabled = true;

        try {
            const result = await api("/api/admin/self-test", { method: "POST" });
            window.alert(
                `Sistemski test je uspješno završen.\n\n` +
                `Provjere: ${result.checks.length}\n` +
                `Testni obračun: ${result.total} KM\n\n` +
                `Testni podaci su automatski poništeni i nisu ostali u bazi.`,
            );
            await loadAdminSystem();
        } catch (error) {
            window.alert(`Sistemski test nije prošao.\n\n${error.message}`);
        } finally {
            button.disabled = false;
        }
    });

    document.getElementById("backup-restore-input")?.addEventListener("change", async (event) => {
        const input = event.currentTarget;
        const file = input.files?.[0];
        if (!file) return;

        try {
            if (file.size > 10 * 1024 * 1024) {
                throw new Error("Backup je veći od dozvoljenih 10 MB.");
            }

            const content = await file.text();
            if (!window.confirm(
                "PAŽNJA: vraćanje backupa zamijeniće postojeće poslovne podatke podacima iz odabranog backupa. " +
                "Prije nastavka napravite novi backup trenutnog stanja.\n\nNastaviti?",
            )) {
                return;
            }

            const button = document.querySelector(".backup-restore-label");
            if (button) button.classList.add("disabled");

            await api("/api/admin/backup/restore", {
                method: "POST",
                headers: { "Content-Type": "text/plain" },
                body: content,
            });

            window.alert("Backup je uspješno vraćen. Sada ćete biti odjavljeni radi sigurnosti.");
            await logout();
        } catch (error) {
            window.alert(`Vraćanje backupa nije uspjelo.\n\n${error.message}`);
        } finally {
            input.value = "";
            document.querySelector(".backup-restore-label")?.classList.remove("disabled");
        }
    });

    document.getElementById("refresh-audit")?.addEventListener("click", loadAdminSystem);

    document.querySelectorAll("[data-system-issue]").forEach((button) => {
        button.addEventListener("click", () => {
            const pages = {
                orders_without_measurement: "orders",
                measured_without_invoice: "orders",
                prices_without_value: "pricing",
            };
            const page = pages[button.dataset.systemIssue];
            if (page) navigate(page);
        });
    });
}

async function downloadBackupFile(filename) {
    const response = await fetch(`/api/admin/backup/${encodeURIComponent(filename)}`, {
        credentials: "same-origin",
    });
    if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || "Backup nije moguće preuzeti.");
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

async function handleOrderSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector(".primary-button");
    button.disabled = true;

    try {
        const body = Object.fromEntries(new FormData(form).entries());
        const orderId = form.dataset.orderId;
        const data = await api(
            orderId ? `/api/orders/${orderId}` : "/api/orders",
            { method: orderId ? "PUT" : "POST", body },
        );
        document.getElementById("modal-root").innerHTML = "";
        await openOrderDetail(data.order.id);
    } catch (error) {
        button.disabled = false;
        window.alert(error.message);
    }
}

async function handleOrderItemSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector(".primary-button");
    button.disabled = true;

    try {
        const body = Object.fromEntries(new FormData(form).entries());
        const deliveryPrice = Number(body.deliveryPrice || 0);

        await api(`/api/orders/${window.currentOrderDetailId}/delivery`, {
            method: "PATCH",
            body: JSON.stringify({ price: deliveryPrice }),
        });

        delete body.deliveryPrice;
        await api(`/api/orders/${window.currentOrderDetailId}/items`, {
            method: "POST",
            body,
        });

        document.getElementById("modal-root").innerHTML = "";
        await openOrderDetail(window.currentOrderDetailId);
    } catch (error) {
        button.disabled = false;
        window.alert(error.message);
    }
}

function openModal(html) {
    const root = document.getElementById("modal-root");
    root.innerHTML = html;

    root.querySelectorAll("[data-close-modal]").forEach((element) => {
        element.addEventListener("click", (event) => {
            if (event.target === element) root.innerHTML = "";
        });
    });

    const customerFormElement = root.querySelector("#customer-form");
    if (customerFormElement) {
        initializeCustomerMap();
        customerFormElement.addEventListener("submit", handleCustomerSubmit);
    }

    const orderFormElement = root.querySelector("#order-form");
    if (orderFormElement) {
        orderFormElement.addEventListener("submit", handleOrderSubmit);
    }

    const itemFormElement = root.querySelector("#order-item-form");
    if (itemFormElement) {
        bindOrderItemCalculation();
        itemFormElement.addEventListener("submit", handleOrderItemSubmit);
    }
}

function bindUserActions() {
    document.getElementById("add-user")?.addEventListener("click", () => openModal(userForm()));
    document.querySelectorAll(".edit-user").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                const data = await api("/api/admin/users");
                const user = data.users.find((item) => item.id === button.dataset.userId);
                if (user) openModal(userForm(user));
            } catch (error) {
                window.alert(error.message);
            }
        });
    });
}

function bindRoleActions() {
    document.getElementById("add-role")?.addEventListener("click", () => openModal(roleForm()));
    document.querySelectorAll(".edit-role").forEach((button) => {
        button.addEventListener("click", () => {
            const role = rolesData.find((item) => item.code === button.dataset.roleCode);
            if (role) openModal(roleForm(role));
        });
    });
}

async function handleUserSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const id = form.dataset.userId;
    const payload = {
        firstName: form.firstName.value.trim(),
        lastName: form.lastName.value.trim(),
        username: form.username.value.trim(),
        role: form.role.value,
        password: form.password.value,
        isActive: form.isActive.checked,
    };

    try {
        await api(id ? `/api/admin/users/${id}` : "/api/admin/users", {
            method: id ? "PUT" : "POST",
            body: JSON.stringify(payload),
        });
        document.getElementById("modal-root").innerHTML = "";
        rolesData = [];
        await showAdminTab("users");
    } catch (error) {
        window.alert(error.message);
    }
}

async function handleRoleSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const code = form.dataset.roleCode;
    const permissions = [...form.querySelectorAll('input[name="permission"]:checked')]
        .map((input) => input.value);
    const payload = {
        name: form.name.value.trim(),
        description: form.description.value.trim(),
        permissions,
    };

    try {
        await api(code ? `/api/admin/roles/${code}` : "/api/admin/roles", {
            method: code ? "PUT" : "POST",
            body: JSON.stringify(payload),
        });
        document.getElementById("modal-root").innerHTML = "";
        rolesData = [];
        await loadAdminData();
        await showAdminTab("roles");
    } catch (error) {
        window.alert(error.message);
    }
}


async function handleModalClick(event) {
    const userButton = event.target.closest("#delete-user");
    if (userButton) {
        if (!window.confirm("Obrisati ovog korisnika? Ova radnja se ne može poništiti.")) return;
        try {
            await api(`/api/admin/users/${userButton.dataset.userId}`, { method: "DELETE" });
            document.getElementById("modal-root").innerHTML = "";
            await showAdminTab("users");
        } catch (error) {
            window.alert(error.message);
        }
    }

    const roleButton = event.target.closest("#delete-role");
    if (roleButton) {
        if (!window.confirm("Obrisati ovu ulogu?")) return;
        try {
            await api(`/api/admin/roles/${roleButton.dataset.roleCode}`, { method: "DELETE" });
            document.getElementById("modal-root").innerHTML = "";
            rolesData = [];
            await loadAdminData();
            await showAdminTab("roles");
        } catch (error) {
            window.alert(error.message);
        }
    }
}

function bindDashboard() {
    document.querySelectorAll(".bottom-nav button").forEach((button) => {
        button.addEventListener("click", () => navigate(button.dataset.page));
    });

    document.querySelectorAll("[data-page-label]").forEach((button) => {
        button.addEventListener("click", () => navigateByLabel(button.dataset.pageLabel));
    });

    document.querySelectorAll(".quick-toolbar button").forEach((button) => {
        button.addEventListener("click", () => handleToolbarAction(button.dataset.action));
    });

    document.getElementById("more-actions").addEventListener("click", openMoreActions);
    document.getElementById("menu-toggle").addEventListener("click", openDrawer);
    document.getElementById("user-menu").addEventListener("click", openUserMenu);
    document.getElementById("global-search").addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
            const firstResult = document.querySelector(".global-search-result");
            if (firstResult) firstResult.click();
        }
    });
    bindGlobalSearch();

    document.getElementById("modal-root").addEventListener("click", handleModalClick);
    navigate("home");
}


const orderStatusNames = {
    RECEIVED: "Zaprimljeno",
    WASHING: "Na pranju",
    DRYING: "Sušenje",
    READY: "Spremno",
    DELIVERED: "Isporučeno",
    PAID: "Plaćeno",
    CANCELLED: "Otkazano",
};

function todayIso() {
    const date = new Date();
    const offset = date.getTimezoneOffset();
    return new Date(date.getTime() - offset * 60000).toISOString().slice(0, 10);
}

function ordersContent(orders = [], filters = {}) {
    const search = filters.search || "";
    const dateFrom = filters.dateFrom || "";
    const dateTo = filters.dateTo || "";
    const canCreate = hasPermission("orders.create");
    const canEdit = hasPermission("orders.edit");
    const canDelete = hasPermission("orders.delete");

    const rows = orders.map((order) => `
        <article class="order-card" data-order-id="${escapeHtml(order.id)}">
            <div class="order-card-top">
                <strong>${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</strong>
                <span class="status">${escapeHtml(orderStatusNames[order.status] || order.status)}</span>
            </div>
            <strong>${escapeHtml(order.customerName || "Bez kupca")}</strong>
            <span>${escapeHtml(order.phone || "Bez telefona")}</span>
            <span>${escapeHtml(order.address || "")}${order.city ? ` · ${escapeHtml(order.city)}` : ""}</span>
            <span>📅 ${escapeHtml(order.orderDate)}</span>
            <div class="order-actions">
                <button class="open-order" data-order-id="${escapeHtml(order.id)}">Otvori</button>
                ${order.latitude !== null && order.longitude !== null
                    ? `<button class="navigate-order" data-latitude="${escapeHtml(order.latitude)}" data-longitude="${escapeHtml(order.longitude)}">🚗</button>`
                    : ""}
                ${canEdit ? `<button class="edit-order" data-order-id="${escapeHtml(order.id)}">✏️</button>` : ""}
                ${canDelete ? `<button class="delete-order" data-order-id="${escapeHtml(order.id)}">🗑️</button>` : ""}
            </div>
        </article>
    `).join("");

    return `
        <section class="page-panel">
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">BAZA NARUDŽBI</span>
                    <h2>Narudžbe</h2>
                </div>
                ${canCreate ? `<button class="compact-primary" id="add-order">➕ Dodaj</button>` : ""}
            </div>
            <div class="order-filters">
                <label class="module-search">
                    <span>🔎</span>
                    <input id="order-search" value="${escapeHtml(search)}"
                        placeholder="Broj narudžbe, kupac, telefon..." autocomplete="off">
                </label>
                <label class="date-filter">
                    <span>Od</span>
                    <input id="order-date-from" type="date" value="${escapeHtml(dateFrom)}">
                </label>
                <label class="date-filter">
                    <span>Do</span>
                    <input id="order-date-to" type="date" value="${escapeHtml(dateTo)}">
                </label>
                <button class="secondary-button" id="clear-order-filters" type="button">Očisti</button>
            </div>
            <div class="filter-hint">Pretraga radi po broju narudžbe, kupcu, telefonu i adresi. Datum filtrira narudžbe po datumu.</div>
            <div id="order-list" class="order-list">
                ${rows || '<div class="empty-state">Nema pronađenih narudžbi.</div>'}
            </div>
        </section>
    `;
}

function orderForm(customers, order = null, selectedCustomerId = "") {
    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <h2>${order ? "Izmijeni narudžbu" : "Nova narudžba"}</h2>
                <form id="order-form" ${order ? `data-order-id="${escapeHtml(order.id)}"` : ""}>
                    <div class="order-customer-picker">
                        <label>Kupac
                            <select name="customerId" required>
                                <option value="">— Odaberi kupca —</option>
                                ${customers.map((customer) => {
                                    const name = customer.companyName ||
                                        `${customer.firstName} ${customer.lastName}`.trim();
                                    return `<option value="${escapeHtml(customer.id)}"
                                        ${(order?.customerId === customer.id || (!order && selectedCustomerId === customer.id)) ? "selected" : ""}>
                                        ${escapeHtml(name)}
                                    </option>`;
                                }).join("")}
                            </select>
                        </label>
                        ${!order && hasPermission("customers.create")
                            ? `<button type="button" class="secondary-button order-new-customer" id="order-new-customer">➕ Novi kupac</button>`
                            : ""}
                    </div>

                    <div id="selected-customer-info" class="order-customer-box">
                        ${order
                            ? `
                                <strong>${escapeHtml(order.customerName)}</strong>
                                ${order.address ? `<span>📍 ${escapeHtml(order.address)}${order.city ? ` · ${escapeHtml(order.city)}` : ""}</span>` : ""}
                                ${order.phone ? `<span>📞 ${escapeHtml(order.phone)}</span>` : ""}
                            `
                            : `<span>Izaberi kupca da se automatski prikažu adresa i telefon.</span>`}
                    </div>

                    <label>Datum
                        <input name="orderDate" type="date"
                            value="${escapeHtml(order?.orderDate || todayIso())}" required>
                    </label>

                    <label>Napomena
                        <textarea name="note" rows="3" maxlength="5000"
                            placeholder="Napomena za preuzimanje...">${escapeHtml(order?.note || "")}</textarea>
                    </label>

                    <button class="primary-button">${order ? "Sačuvaj izmjene" : "Sačuvaj narudžbu"}</button>
                </form>
            </section>
        </div>
    `;
}

function bindOrderCustomerPreview() {
    const form = document.getElementById("order-form");
    const info = document.getElementById("selected-customer-info");
    if (!form || !info) return;

    document.getElementById("order-new-customer")?.addEventListener("click", () => {
        openModal(customerForm(null, true));
    });

    const update = async () => {
        const customerId = form.customerId.value;
        if (!customerId) {
            info.innerHTML = "<span>Izaberi kupca da se automatski prikažu adresa i telefon.</span>";
            return;
        }

        try {
            const data = await api(`/api/customers/${customerId}`);
            const customer = data.customer;
            const name = customer.companyName ||
                `${customer.firstName} ${customer.lastName}`.trim();
            info.innerHTML = `
                <strong>${escapeHtml(name)}</strong>
                ${customer.address ? `<span>📍 ${escapeHtml(customer.address)}${customer.city ? ` · ${escapeHtml(customer.city)}` : ""}</span>` : ""}
                ${customer.phone ? `<span>📞 ${escapeHtml(customer.phone)}</span>` : ""}
            `;
        } catch (error) {
            info.innerHTML = `<span>${escapeHtml(error.message)}</span>`;
        }
    };

    form.customerId.addEventListener("change", update);
}

async function loadCustomersForOrder() {
    const data = await api("/api/customers?search=");
    return data.customers;
}

async function loadOrders(search = "", dateFrom = "", dateTo = "") {
    const params = new URLSearchParams({
        search,
        dateFrom,
        dateTo,
    });
    const data = await api(`/api/orders?${params.toString()}`);
    const content = document.getElementById("page-content");
    content.innerHTML = ordersContent(data.orders, { search, dateFrom, dateTo });
    bindOrders();
}

function bindOrders() {
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));

    document.getElementById("add-order")?.addEventListener("click", async () => {
        try {
            openModal(orderForm(await loadCustomersForOrder()));
            bindOrderCustomerPreview();
        } catch (error) {
            window.alert(error.message);
        }
    });

    const searchInput = document.getElementById("order-search");
    const dateFromInput = document.getElementById("order-date-from");
    const dateToInput = document.getElementById("order-date-to");
    const clearFiltersButton = document.getElementById("clear-order-filters");
    let timer;

    const reloadWithFilters = () => loadOrders(
        searchInput?.value.trim() || "",
        dateFromInput?.value || "",
        dateToInput?.value || "",
    );

    searchInput?.addEventListener("input", () => {
        clearTimeout(timer);
        timer = setTimeout(reloadWithFilters, 250);
    });

    dateFromInput?.addEventListener("change", reloadWithFilters);
    dateToInput?.addEventListener("change", reloadWithFilters);
    clearFiltersButton?.addEventListener("click", () => loadOrders());

    document.querySelectorAll(".open-order").forEach((button) => {
        button.addEventListener("click", () => openOrderDetail(button.dataset.orderId));
    });

    document.querySelectorAll(".navigate-order").forEach((button) => {
        button.addEventListener("click", () => openNavigation(
            Number(button.dataset.latitude),
            Number(button.dataset.longitude),
        ));
    });

    document.querySelectorAll(".edit-order").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                const data = await api(`/api/orders/${button.dataset.orderId}`);
                openModal(orderForm(await loadCustomersForOrder(), data.order));
                bindOrderCustomerPreview();
            } catch (error) {
                window.alert(error.message);
            }
        });
    });

    document.querySelectorAll(".delete-order").forEach((button) => {
        button.addEventListener("click", async () => {
            if (!window.confirm("Obrisati ovu narudžbu i njene stavke?")) return;
            try {
                await api(`/api/orders/${button.dataset.orderId}`, { method: "DELETE" });
                await loadOrders(searchInput?.value.trim() || "");
            } catch (error) {
                window.alert(error.message);
            }
        });
    });
}

function orderDetailContent(order, items, targetItemId = "", qrScan = null) {
    const canEdit = hasPermission("orders.edit");
    const targetItemIndex = targetItemId
        ? items.findIndex((item) => item.id === targetItemId)
        : -1;
    const itemsTotal = items.reduce((sum, item) => sum + Number(item.total || 0), 0);
    const deliveryPrice = Number(order.deliveryPrice || 0);
    const total = Number((itemsTotal + deliveryPrice).toFixed(2));
    const invoiceStatus = invoiceStatusLabel(order);

    return `
        <section class="page-panel order-detail">
            <button class="back-button" data-go-orders>← Narudžbe</button>

            <div class="panel-heading">
                <div>
                    <span class="eyebrow">NARUDŽBA</span>
                    <h2>${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</h2>
                </div>
            </div>

            ${targetItemIndex >= 0
                ? `<div class="qr-target-banner" role="status">
                    📷 <strong>QR kod pronađen:</strong> otvoren je tepih <strong>${targetItemIndex + 1}/${items.length}</strong> iz narudžbe <strong>${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</strong>.
                    ${qrScan
                        ? `<span class="qr-scan-confirmation">✓ Evidentirano skeniranje #${qrScan.scanCount}${qrScan.lastScannedAt ? ` · ${escapeHtml(formatDateTimeBs(qrScan.lastScannedAt))}` : ""}</span>`
                        : `<span class="qr-scan-confirmation qr-scan-warning">⚠ Evidencija skeniranja trenutno nije dostupna.</span>`}
                </div>`
                : ""}

            <div class="workflow-step order-workflow-step">
                <div class="workflow-step-number">1</div>
                <div class="workflow-step-content">
                    <span class="eyebrow">NARUDŽBA</span>
                    <h3>${escapeHtml(order.customerName || "Bez kupca")}</h3>
                    ${order.address ? `<span>📍 ${escapeHtml(order.address)}${order.city ? ` · ${escapeHtml(order.city)}` : ""}</span>` : ""}
                    ${order.phone ? `<span>📞 ${escapeHtml(order.phone)}</span>` : ""}
                    <span>📅 ${escapeHtml(formatDateBs(order.orderDate))}</span>
                    ${order.note ? `<div class="note-box">📝 ${escapeHtml(order.note)}</div>` : ""}
                    ${order.latitude !== null && order.longitude !== null
                        ? `<button class="secondary-button" id="order-navigation"
                            data-latitude="${escapeHtml(order.latitude)}"
                            data-longitude="${escapeHtml(order.longitude)}">🚗 Navigacija</button>` : ""}
                </div>
            </div>

            <div class="workflow-step measurement-workflow-step">
                <div class="workflow-step-number">2</div>
                <div class="workflow-step-content">
                    <span class="eyebrow">MJERENJE</span>
                    <h3>Mjerenje kada tepisi stignu u firmu</h3>
                    <p>Kupac, telefon i adresa već su povezani sa ${escapeHtml(order.orderCode || `N${order.orderNumber}`)}. Ovdje se unose samo mjere, usluga, cijena i napomena za tepih.</p>

                    <div class="measurement-summary">
                        ${items.map((item, index) => `
                            <div class="measurement-summary-row${item.id === targetItemId ? " qr-target-item" : ""}"
                                id="order-item-${escapeHtml(item.id)}">
                                <div class="measurement-summary-main">
                                    <strong>${index + 1}/${items.length} · ${escapeHtml(item.serviceName)}</strong>
                                    <span>${item.unit === "m2"
                                        ? `${escapeHtml(item.lengthM)} × ${escapeHtml(item.widthM)} m · ${escapeHtml(item.areaM2)} m²`
                                        : `${escapeHtml(item.quantity)} kom.`}</span>
                                    ${item.note ? `<small>📝 ${escapeHtml(item.note)}</small>` : ""}
                                    ${item.qrScanCount
                                        ? `<small class="qr-scan-meta">📷 QR skeniran ${item.qrScanCount}×${item.lastQrScannedAt ? ` · ${escapeHtml(formatDateTimeBs(item.lastQrScannedAt))}` : ""}</small>`
                                        : ""}
                                </div>
                                <div class="measurement-summary-actions">
                                    <strong>${formatKm(item.total)} KM</strong>
                                    ${canEdit
                                        ? `<button class="icon-button danger delete-order-item"
                                            data-order-id="${escapeHtml(order.id)}"
                                            data-item-id="${escapeHtml(item.id)}"
                                            title="Ukloni mjerenje" aria-label="Ukloni mjerenje">🗑️</button>`
                                        : ""}
                                </div>
                            </div>
                        `).join("") || '<div class="empty-state compact-empty">Mjerenje još nije uneseno.</div>'}
                    </div>

                    <div class="workflow-actions">
                        ${canEdit ? `<button class="compact-primary" id="open-measurement">📏 ${items.length ? "Dodaj još mjerenje" : "Unesi mjerenje"}</button>` : ""}
                        ${hasPermission("labels.view") && items.length
                            ? `<button class="secondary-button" id="open-order-labels">🏷️ Etikete (${items.length})</button>`
                            : ""}
                    </div>
                </div>
            </div>

            <div class="workflow-step invoice-workflow-step">
                <div class="workflow-step-number">3</div>
                <div class="workflow-step-content">
                    <div class="workflow-heading-row">
                        <div>
                            <span class="eyebrow">RAČUN</span>
                            <h3>${order.invoiceNumber ? escapeHtml(invoiceNumber(order)) : "Račun još nije snimljen"}</h3>
                        </div>
                        <span class="invoice-status-badge ${invoiceStatusClass(order)}">${invoiceStatus}</span>
                    </div>
                    <p>Račun automatski koristi podatke narudžbe i sva unesena mjerenja.</p>
                    ${hasPermission("invoices.view")
                        ? `<div class="workflow-actions">
                            <button class="secondary-button" id="open-order-invoice">🧾 ${order.invoiceNumber ? "Otvori račun" : "Napravi račun"}</button>
                        </div>`
                        : ""}
                </div>
            </div>

            <div class="workflow-summary">
                <strong>${escapeHtml(order.orderCode || `N${order.orderNumber}`)}</strong>
                <span>Narudžba → Mjerenje → Račun</span>
            </div>

            <div class="order-total-breakdown">
                <div><span>Tepisi</span><strong>${itemsTotal.toFixed(2)} KM</strong></div>
                <div><span>Dostava</span><strong>${deliveryPrice.toFixed(2)} KM</strong></div>
                <div class="order-total">
                    <span>UKUPNO</span>
                    <strong>${total.toFixed(2)} KM</strong>
                </div>
            </div>
        </section>
    `;
}

function orderItemForm(order, prices = []) {
    const deliveryPrice = Number(order.deliveryPrice || 0);

    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <h2>📏 Mjerenje</h2>

                <div class="order-customer-box">
                    <strong>${escapeHtml(order.customerName)}</strong>
                    ${order.address ? `<span>📍 ${escapeHtml(order.address)}${order.city ? ` · ${escapeHtml(order.city)}` : ""}</span>` : ""}
                    ${order.phone ? `<span>📞 ${escapeHtml(order.phone)}</span>` : ""}
                </div>

                <form id="order-item-form" data-order-id="${escapeHtml(order.id)}">
                    <input type="hidden" name="unit" value="m2">
                    <label>Usluga
                        <select name="serviceName" required>
                            <option value="">Izaberi uslugu</option>
                            ${prices.map((item) => `<option value="${escapeHtml(item.serviceName)}" data-unit="${escapeHtml(item.unit)}" data-price="${escapeHtml(item.price)}">${escapeHtml(item.serviceName)} — ${item.price.toFixed(2)} KM / ${item.unit === "m2" ? "m²" : "kom."}</option>`).join("")}
                        </select>
                    </label>

                    <label>Dužina (m)
                        <input name="lengthM" type="number" min="0.01" step="0.01" inputmode="decimal" required>
                    </label>

                    <label>Širina (m)
                        <input name="widthM" type="number" min="0.01" step="0.01" inputmode="decimal" required>
                    </label>

                    <label>Cijena (KM / m²)
                        <input name="unitPrice" type="number" min="0" step="0.01" inputmode="decimal" required>
                    </label>

                    <div id="item-calculation" class="calculation-box">Unesi dužinu, širinu i cijenu.</div>

                    <label>🚚 Cijena dostave (KM)
                        <input name="deliveryPrice" type="number" min="0" max="1000000" step="0.01"
                            inputmode="decimal" value="${deliveryPrice.toFixed(2)}">
                    </label>

                    <div id="measurement-total" class="calculation-box">
                        Dostava: ${deliveryPrice.toFixed(2)} KM
                    </div>

                    <label>Napomena
                        <textarea name="itemNote" rows="3" maxlength="2000"
                            placeholder="Napomena za tepih..."></textarea>
                    </label>

                    <button class="primary-button">➕ Dodaj stavku</button>
                </form>
            </section>
        </div>
    `;
}


async function recordQrScan(orderId, itemId) {
    return api(
        `/api/qr/order/${encodeURIComponent(orderId)}/item/${encodeURIComponent(itemId)}/scan`,
        { method: "POST" },
    );
}

async function openOrderDetail(orderId, targetItemId = "") {
    try {
        const data = await api(`/api/orders/${orderId}`);
        const targetExists = !targetItemId || data.items.some((item) => item.id === targetItemId);

        if (!targetExists) {
            window.alert("QR kod je nevažeći ili tepih više ne postoji u ovoj narudžbi.");
            return false;
        }

        let qrScan = null;
        if (targetItemId) {
            try {
                qrScan = await recordQrScan(orderId, targetItemId);
                const targetItem = data.items.find((item) => item.id === targetItemId);
                if (targetItem) {
                    targetItem.qrScanCount = qrScan.scanCount;
                    targetItem.lastQrScannedAt = qrScan.lastScannedAt;
                }
            } catch (error) {
                console.error("Evidencija QR skeniranja nije uspjela:", error);
            }
        }

        const content = document.getElementById("page-content");
        content.innerHTML = orderDetailContent(data.order, data.items, targetItemId, qrScan);
        window.currentOrderDetailId = orderId;
        bindOrderDetail();

        if (targetItemId) {
            requestAnimationFrame(() => {
                const target = document.getElementById(`order-item-${targetItemId}`);
                target?.scrollIntoView({ behavior: "smooth", block: "center" });
            });
        }

        return true;
    } catch (error) {
        window.alert(error.message);
        return false;
    }
}

function bindOrderDetail() {
    document.querySelector("[data-go-orders]")?.addEventListener("click", () => navigate("orders"));
    document.getElementById("order-navigation")?.addEventListener("click", (event) => {
        openNavigation(Number(event.currentTarget.dataset.latitude), Number(event.currentTarget.dataset.longitude));
    });
    document.getElementById("open-order-invoice")?.addEventListener("click", () => {
        openInvoice(window.currentOrderDetailId);
    });
    document.getElementById("open-order-labels")?.addEventListener("click", () => {
        openLabels(window.currentOrderDetailId);
    });

    document.getElementById("open-measurement")?.addEventListener("click", async () => {
        try {
            const data = await api(`/api/orders/${window.currentOrderDetailId}`);
            const prices = (await loadPricing()).filter((item) => item.unit === "m2");
            openModal(orderItemForm(data.order, prices));
            bindOrderItemServicePreview();
        } catch (error) {
            window.alert(error.message);
        }
    });

    document.querySelectorAll(".delete-order-item").forEach((button) => {
        button.addEventListener("click", async () => {
            if (!window.confirm("Obrisati ovu stavku?")) return;
            try {
                await api(`/api/orders/${button.dataset.orderId}/items/${button.dataset.itemId}`, { method: "DELETE" });
                await openOrderDetail(button.dataset.orderId);
            } catch (error) {
                window.alert(error.message);
            }
        });
    });
}

function bindOrderItemServicePreview() {
    const form = document.getElementById("order-item-form");
    const service = form?.querySelector('[name="serviceName"]');
    const price = form?.querySelector('[name="unitPrice"]');
    const unit = form?.querySelector('[name="unit"]');
    const length = form?.querySelector('[name="lengthM"]');
    const width = form?.querySelector('[name="widthM"]');
    if (!service || !price) return;

    service.addEventListener("change", () => {
        const option = service.selectedOptions[0];
        const selectedPrice = Number(option?.dataset.price);
        const selectedUnit = option?.dataset.unit || "m2";
        if (unit) unit.value = selectedUnit;
        if (Number.isFinite(selectedPrice)) price.value = selectedPrice.toFixed(2);
        if (selectedUnit === "m2") {
            length.required = true;
            width.required = true;
            length.closest("label").classList.remove("hidden");
            width.closest("label").classList.remove("hidden");
            price.closest("label").querySelector("span")?.remove();
        }
    });

    service.dispatchEvent(new Event("change"));
}

function bindOrderItemCalculation() {
    const form = document.getElementById("order-item-form");
    const calculation = document.getElementById("item-calculation");
    const measurementTotal = document.getElementById("measurement-total");
    if (!form || !calculation || !measurementTotal) return;

    const update = () => {
        const length = Number(form.lengthM.value);
        const width = Number(form.widthM.value);
        const price = Number(form.unitPrice.value);
        const deliveryPrice = Number(form.deliveryPrice.value || 0);

        if (deliveryPrice < 0 || deliveryPrice > 1000000) {
            measurementTotal.textContent = "Cijena dostave nije ispravna.";
        } else {
            measurementTotal.textContent = `Dostava: ${deliveryPrice.toFixed(2)} KM`;
        }

        if (length > 0 && width > 0 && price >= 0) {
            const area = Number((length * width).toFixed(2));
            const carpetTotal = Number((area * price).toFixed(2));
            const total = Number((carpetTotal + Math.max(0, deliveryPrice)).toFixed(2));
            calculation.textContent =
                `${area.toFixed(2)} m² × ${price.toFixed(2)} KM = ${carpetTotal.toFixed(2)} KM`;
            measurementTotal.textContent += ` · Ukupno: ${total.toFixed(2)} KM`;
            return;
        }

        calculation.textContent = "Unesi dužinu, širinu i cijenu.";
    };

    ["change", "input"].forEach((eventName) => {
        form.addEventListener(eventName, update);
    });

    update();
}



async function loadPricing(includeInactive = false) {
    const data = await api("/api/pricing");
    return includeInactive ? data.prices : data.prices.filter((item) => item.isActive);
}

function pricingContent(prices) {
    const canEdit = hasPermission("pricing.edit");
    return `
        <section class="page-panel">
            <button class="back-button" data-go-home>← Početna</button>
            <div class="panel-heading">
                <div>
                    <span class="eyebrow">CJENOVNIK</span>
                    <h2>Usluge i cijene</h2>
                </div>
                ${canEdit ? '<button class="compact-primary" id="add-price">➕ Dodaj</button>' : ""}
            </div>
            <p class="section-description">Ovdje podešavaš osnovne cijene. Kada dodaš novu mjernu stavku, cijena se automatski ponudi. Cijena se čuva i na samoj narudžbi.</p>
            <div class="pricing-list">
                ${prices.map((item) => `
                    <article class="pricing-card ${item.isActive ? "" : "is-inactive"}">
                        <div>
                            <strong>${escapeHtml(item.serviceName)}</strong>
                            <span>${item.unit === "m2" ? "m²" : "komad"} · ${item.isActive ? "Aktivno" : "Neaktivno"}</span>
                        </div>
                        <div class="pricing-card-right">
                            <strong>${item.price.toFixed(2)} KM</strong>
                            ${canEdit ? `
                                <button class="edit-price" data-price-id="${escapeHtml(item.id)}">✏️</button>
                                <button class="delete-price" data-price-id="${escapeHtml(item.id)}" ${item.isActive ? "" : "disabled"}>🗑️</button>
                            ` : ""}
                        </div>
                    </article>
                `).join("") || '<div class="empty-state">Cjenovnik je prazan.</div>'}
            </div>
        </section>
    `;
}

function priceForm(price = null) {
    const isEdit = Boolean(price);
    return `
        <div class="modal-backdrop" data-close-modal>
            <section class="modal-card" role="dialog" aria-modal="true">
                <button class="modal-close" data-close-modal>×</button>
                <h2>${isEdit ? "✏️ Izmijeni cijenu" : "➕ Nova usluga"}</h2>
                <form id="price-form" data-price-id="${price ? escapeHtml(price.id) : ""}">
                    <label>Naziv usluge
                        <input name="serviceName" maxlength="200" required
                            value="${escapeHtml(price?.serviceName || "")}"
                            placeholder="npr. Pranje tepiha">
                    </label>
                    <label>Jedinica naplate
                        <select name="unit">
                            <option value="m2" ${price?.unit === "m2" || !price ? "selected" : ""}>m²</option>
                            <option value="piece" ${price?.unit === "piece" ? "selected" : ""}>Komad</option>
                        </select>
                    </label>
                    <label>Cijena (KM)
                        <input name="price" type="number" min="0" max="1000000" step="0.01"
                            inputmode="decimal" required value="${price ? price.price.toFixed(2) : "0.00"}">
                    </label>
                    <label>Redoslijed
                        <input name="sortOrder" type="number" min="0" max="1000000" step="1"
                            inputmode="numeric" value="${price ? price.sortOrder : "0"}">
                    </label>
                    <label class="checkbox-row">
                        <input name="isActive" type="checkbox" ${price?.isActive !== false ? "checked" : ""}>
                        Aktivna usluga
                    </label>
                    <button class="primary-button">${isEdit ? "Sačuvaj izmjene" : "Dodaj u cjenovnik"}</button>
                </form>
            </section>
        </div>
    `;
}

async function loadPricingPage() {
    const prices = await loadPricing(true);
    const content = document.getElementById("page-content");
    content.innerHTML = pricingContent(prices);
    bindPricing();
}

function bindPricing() {
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));

    document.getElementById("add-price")?.addEventListener("click", () => {
        openModal(priceForm());
    });

    document.querySelectorAll(".edit-price").forEach((button) => {
        button.addEventListener("click", async () => {
            try {
                const prices = await loadPricing(true);
                const price = prices.find((item) => item.id === button.dataset.priceId);
                if (!price) throw new Error("Stavka cjenovnika nije pronađena.");
                openModal(priceForm(price));
            } catch (error) {
                window.alert(error.message);
            }
        });
    });

    document.querySelectorAll(".delete-price").forEach((button) => {
        button.addEventListener("click", async () => {
            if (!window.confirm("Deaktivirati ovu uslugu?")) return;
            try {
                await api(`/api/pricing/${button.dataset.priceId}`, { method: "DELETE" });
                await loadPricingPage();
            } catch (error) {
                window.alert(error.message);
            }
        });
    });
}

async function handlePriceSubmit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const payload = {
        serviceName: form.serviceName.value,
        unit: form.unit.value,
        price: Number(form.price.value),
        sortOrder: Number(form.sortOrder.value || 0),
        isActive: form.isActive.checked,
    };

    try {
        const method = form.dataset.priceId ? "PUT" : "POST";
        const url = form.dataset.priceId ? `/api/pricing/${form.dataset.priceId}` : "/api/pricing";
        await api(url, { method, body: JSON.stringify(payload) });
        closeModal();
        await loadPricingPage();
    } catch (error) {
        window.alert(error.message);
    }
}

async function navigate(page) {
    const content = document.getElementById("page-content");
    if (page === "home") {
        content.innerHTML = homeContent();
        await loadDashboard();
        return;
    }

    if (page === "admin" && currentUser.role === "ADMIN") {
        content.innerHTML = adminContent();
        rolesData = [];
        await showAdminTab("users");
        bindAdminTabs();
        return;
    }

    if (page === "customers") {
        if (!hasPermission("customers.view")) {
            content.innerHTML = placeholderContent("Nemaš dozvolu za Kupce");
            content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
            return;
        }

        try {
            await loadCustomers();
        } catch (error) {
            content.innerHTML = placeholderContent("Greška pri učitavanju kupaca");
            window.alert(error.message);
        }
        return;
    }

    if (page === "pricing") {
        if (!hasPermission("pricing.view")) {
            content.innerHTML = placeholderContent("Nemaš dozvolu za Cjenovnik");
            content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
            return;
        }

        try {
            await loadPricingPage();
        } catch (error) {
            content.innerHTML = placeholderContent("Greška pri učitavanju cjenovnika");
            window.alert(error.message);
        }
        return;
    }

    if (page === "labels" || page === "qr") {
        const permission = page === "labels" ? "labels.view" : "qr.view";
        if (!hasPermission(permission)) {
            content.innerHTML = placeholderContent(page === "labels" ? "Nemaš dozvolu za Etikete" : "Nemaš dozvolu za QR kod");
            content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
            return;
        }

        try {
            await loadLabelsPage();
        } catch (error) {
            content.innerHTML = placeholderContent("Greška pri učitavanju etiketa");
            window.alert(error.message);
        }
        return;
    }

    if (page === "reports") {
        if (!hasPermission("reports.view")) {
            content.innerHTML = placeholderContent("Nemaš dozvolu za Izvještaje");
            content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
            return;
        }

        try {
            await loadReports();
        } catch (error) {
            content.innerHTML = placeholderContent("Greška pri učitavanju izvještaja");
            window.alert(error.message);
        }
        return;
    }

    if (page === "invoices") {
        if (!hasPermission("invoices.view")) {
            content.innerHTML = placeholderContent("Nemaš dozvolu za Račune");
            content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
            return;
        }

        try {
            await loadInvoices();
        } catch (error) {
            content.innerHTML = placeholderContent("Greška pri učitavanju računa");
            window.alert(error.message);
        }
        return;
    }

    if (page === "orders") {
        if (!hasPermission("orders.view")) {
            content.innerHTML = placeholderContent("Nemaš dozvolu za Narudžbe");
            content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
            return;
        }

        try {
            await loadOrders();
        } catch (error) {
            content.innerHTML = placeholderContent("Greška pri učitavanju narudžbi");
            window.alert(error.message);
        }
        return;
    }

    content.innerHTML = placeholderContent("Modul");
    content.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
}

function navigateByLabel(label) {
    if (label === "Kupci") return navigate("customers");
    if (label === "Narudžbe" || label === "Nova narudžba") return navigate("orders");
    if (label === "Cjenovnik") return navigate("pricing");
    if (label === "Etikete") return navigate("labels");
    if (label === "QR kod") return navigate("qr");
    if (label === "Računi") return navigate("invoices");
    if (label === "Izvještaji") return navigate("reports");
    if (label === "Administrator") return navigate("admin");
    document.getElementById("page-content").innerHTML = placeholderContent(label);
    document.querySelector("[data-go-home]")?.addEventListener("click", () => navigate("home"));
}

function bindAdminTabs() {
    document.querySelectorAll("[data-admin-tab]").forEach((button) => {
        button.addEventListener("click", () => showAdminTab(button.dataset.adminTab));
    });
}

function openMoreActions() {
    const drawer = document.getElementById("drawer");
    drawer.innerHTML = `
        <div class="drawer-backdrop" data-close-drawer></div>
        <section class="action-drawer">
            <h3>Dodatne radnje</h3>
            <button data-action="edit">✏️ Izmijeni</button>
            <button data-action="export">📤 Izvoz</button>
            <button data-action="import">📥 Uvoz Excel</button>
        </section>
    `;
    drawer.classList.remove("hidden");
    drawer.querySelectorAll("button[data-action]").forEach((button) => {
        button.addEventListener("click", () => {
            drawer.classList.add("hidden");
            handleToolbarAction(button.dataset.action);
        });
    });
    drawer.querySelector("[data-close-drawer]").addEventListener("click", () => {
        drawer.classList.add("hidden");
    });
}

function openDrawer() {
    const drawer = document.getElementById("drawer");
    drawer.innerHTML = `
        <div class="drawer-backdrop" data-close-drawer></div>
        <section class="action-drawer side-menu">
            <h3>Meni</h3>
            ${mainMenu.map(([icon, title, description, permission]) =>
                hasPermission(permission) ? `<button data-page-label="${escapeHtml(title)}">${icon} ${escapeHtml(title)}</button>` : ""
            ).join("")}
            ${currentUser.role === "ADMIN" ? '<button data-page-label="Administrator">⚙️ Administracija</button>' : ""}
            <button id="drawer-logout">🚪 Odjava</button>
        </section>
    `;
    drawer.classList.remove("hidden");
    drawer.querySelectorAll("[data-page-label]").forEach((button) => {
        button.addEventListener("click", () => {
            drawer.classList.add("hidden");
            navigateByLabel(button.dataset.pageLabel);
        });
    });
    drawer.querySelector("[data-close-drawer]").addEventListener("click", () => drawer.classList.add("hidden"));
    drawer.querySelector("#drawer-logout").addEventListener("click", logout);
}

function openUserMenu() {
    const drawer = document.getElementById("drawer");
    drawer.innerHTML = `
        <div class="drawer-backdrop" data-close-drawer></div>
        <section class="action-drawer side-menu">
            <h3>${escapeHtml(currentUser.firstName)} ${escapeHtml(currentUser.lastName)}</h3>
            <p>@${escapeHtml(currentUser.username)} · ${escapeHtml(currentUser.roleName || currentUser.role)}</p>
            <button id="drawer-logout">🚪 Odjava</button>
        </section>
    `;
    drawer.classList.remove("hidden");
    drawer.querySelector("[data-close-drawer]").addEventListener("click", () => drawer.classList.add("hidden"));
    drawer.querySelector("#drawer-logout").addEventListener("click", logout);
}

let globalSearchTimer = null;

async function runGlobalSearch(query) {
    const box = document.getElementById("global-search-results");
    if (!box) return;

    const cleanQuery = query.trim();
    if (cleanQuery.length < 2) {
        box.classList.add("hidden");
        box.innerHTML = "";
        return;
    }

    box.classList.remove("hidden");
    box.innerHTML = '<div class="global-search-loading">Pretražujem...</div>';

    try {
        const data = await api(`/api/search?q=${encodeURIComponent(cleanQuery)}`);
        if (!data.results.length) {
            box.innerHTML = '<div class="global-search-empty">Nema rezultata.</div>';
            return;
        }

        box.innerHTML = data.results.map((result) => {
            const icon = result.type === "order" ? "📋" : result.type === "customer" ? "👤" : "🧾";
            return `
                <button class="global-search-result" data-result-type="${escapeHtml(result.type)}" data-result-id="${escapeHtml(result.id)}">
                    <span>${icon}</span>
                    <span><strong>${escapeHtml(result.title)}</strong><small>${escapeHtml(result.subtitle)}</small></span>
                    <b>›</b>
                </button>
            `;
        }).join("");

        box.querySelectorAll(".global-search-result").forEach((button) => {
            button.addEventListener("click", () => openGlobalSearchResult(
                button.dataset.resultType,
                button.dataset.resultId,
            ));
        });
    } catch (error) {
        box.innerHTML = `<div class="global-search-empty">${escapeHtml(error.message)}</div>`;
    }
}

async function openGlobalSearchResult(type, id) {
    document.getElementById("global-search-results")?.classList.add("hidden");

    try {
        if (type === "order" || type === "invoice") {
            await openOrderDetail(id);
            return;
        }

        if (type === "customer") {
            const data = await api(`/api/customers/${id}`);
            openModal(customerForm(data.customer));
        }
    } catch (error) {
        window.alert(error.message);
    }
}

function bindGlobalSearch() {
    const input = document.getElementById("global-search");
    const box = document.querySelector(".mobile-search");
    if (!input || !box) return;

    const results = document.createElement("div");
    results.id = "global-search-results";
    results.className = "global-search-results hidden";
    box.appendChild(results);

    input.addEventListener("input", () => {
        clearTimeout(globalSearchTimer);
        globalSearchTimer = setTimeout(() => runGlobalSearch(input.value), 250);
    });

    input.addEventListener("focus", () => {
        if (input.value.trim().length >= 2) runGlobalSearch(input.value);
    });

    document.addEventListener("click", (event) => {
        if (!box.contains(event.target)) results.classList.add("hidden");
    });
}

function handleToolbarAction(action) {
    if (action === "print" || action === "pdf") {
        if (document.getElementById("invoice-document")) {
            window.print();
            return;
        }
        if (action === "print") {
            window.print();
            return;
        }
    }

    if (action === "import") {
        document.getElementById("excel-file").click();
        return;
    }

    const messages = {
        add: "Dodavanje će biti povezano sa aktivnim modulom.",
        remove: "Prvo izaberi zapis koji želiš ukloniti.",
        pdf: "PDF će biti povezan sa dokumentom aktivnog modula.",
        search: "Pretraga je dostupna iz gornjeg polja.",
        edit: "Prvo izaberi zapis koji želiš izmijeniti.",
        export: "Izvoz će biti povezan sa aktivnim modulom.",
    };
    window.alert(messages[action] || "Radnja nije dostupna.");
}

async function handleLogin(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = document.getElementById("login-button");
    const errorBox = document.getElementById("login-error");
    button.disabled = true;
    errorBox.classList.add("hidden");

    try {
        const data = await api("/api/login", {
            method: "POST",
            body: JSON.stringify({
                username: form.username.value,
                password: form.password.value,
            }),
        });
        dashboardView(data.user);
        await openPendingQrTarget();
    } catch (error) {
        errorBox.textContent = error.message;
        errorBox.classList.remove("hidden");
        button.disabled = false;
    }
}

async function logout() {
    try {
        await api("/api/logout", { method: "POST" });
    } finally {
        currentUser = null;
        loginView();
    }
}

async function openPendingQrTarget() {
    const params = new URLSearchParams(window.location.search);
    const orderId = params.get("order");
    const itemId = params.get("item");
    if (!orderId) return;

    const opened = await openOrderDetail(orderId, itemId || "");
    if (opened) {
        window.history.replaceState({}, document.title, window.location.pathname);
    }
}

async function loadSession() {
    try {
        const data = await api("/api/me");
        dashboardView(data.user);
        await openPendingQrTarget();
    } catch {
        loginView();
    }
}

document.addEventListener("submit", (event) => {
    if (event.target.id === "user-form") handleUserSubmit(event);
    if (event.target.id === "role-form") handleRoleSubmit(event);
    if (event.target.id === "customer-form") handleCustomerSubmit(event);
    if (event.target.id === "price-form") handlePriceSubmit(event);
});

loadSession();
